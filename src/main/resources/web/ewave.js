'use strict';

(() => {
  const $ = id => document.getElementById(id);
  const by = selector => Array.from(document.querySelectorAll(selector));
  const unavailable = '—';
  const clock = time => time == null ? unavailable : new Date(time).toLocaleTimeString();
  const finite = value => typeof value === 'number' && Number.isFinite(value);
  const signal = value => finite(value) ? Math.round(value) + ' dBm' : unavailable;
  const number = value => finite(value) ? value.toLocaleString() : unavailable;
  const mac = /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
  const recentMs = 5 * 60 * 1000;
  const intelPageSize = 100;
  const timestamp = value => finite(value) ? value : Date.parse(value);
  const state = {
    view: 'intel', wifi: [], topology: {}, status: null,
    profile: null, captureRevision: 0, profileRevision: 0, profileSaving: false,
    scope: 'network', apChoice: null, autoAp: null, intelLimit: intelPageSize,
    audit: null, ssid: null, selected: null, known: new Set(), flashed: new Map(),
    ops: { aps: [], targets: [], lan: [], manual: [], active: null, stage: -1 }
  };
  const pending = new Set();
  const observationNow = () => state.status?.wifi?.referenceTime ?? Date.now();

  function element(tag, value, className) {
    const node = document.createElement(tag);
    if (value != null) node.textContent = value;
    if (className) node.className = className;
    return node;
  }

  async function api(path, body, missing, method = 'GET') {
    const response = await fetch(path, body === undefined ? { cache: 'no-store', method } : {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    });
    if (response.status === missing) return null;
    const json = response.headers.get('Content-Type')?.includes('application/json');
    const result = json ? await response.json() : await response.text();
    if (!response.ok) throw new Error(result.error || result.title || result || 'Request failed (' + response.status + ')');
    return result;
  }

  async function once(key, run) {
    if (pending.has(key)) return;
    pending.add(key);
    try { await run(); } finally { pending.delete(key); }
  }

  function row(values, select, chosen = false) {
    const item = element('tr');
    for (const value of values) item.append(value instanceof HTMLTableCellElement ? value : element('td', value ?? unavailable));
    if (select) {
      item.tabIndex = 0;
      item.classList.toggle('selected', chosen);
      item.addEventListener('click', select);
      item.addEventListener('keydown', event => {
        if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select(); }
      });
    }
    return item;
  }

  function blank(id, visible, message) {
    const item = $(id);
    item.classList.remove('loading');
    item.hidden = !visible;
    if (message) item.textContent = message;
  }

  function normalizeWifi(device) {
    const legacySignal = device.lastRssi === 127 ? null : device.lastRssi;
    const observed = [device.role === 'AP' ? 'Access point' : device.role === 'CLIENT' ? 'Client' : null,
      device.capabilities?.wifiGeneration].filter(value => value && value !== 'Unknown').join(' · ');
    const hint = device.fingerprintHint?.family || (device.guessedType === 'Unknown' ? null : device.guessedType);
    return {
      id: device.id || device.mac, vendor: device.vendor || 'Unknown',
      type: observed || (hint ? hint + ' (hint)' : 'Unknown'),
      rssi: device.rssiMedian ?? legacySignal, distance: finite(device.estimatedMeters) ? device.estimatedMeters.toFixed(1) + ' m' : unavailable,
      first: device.firstSeen, last: device.lastSeen, count: device.packetCount, random: device.locallyAdministered ?? device.isRandomMac,
      names: device.probedSsids || [], details: device
    };
  }

  function tickUptime() {
    const start = state.status?.startedAt;
    const seconds = start ? Math.max(0, Math.floor((Date.now() - start) / 1000)) : 0;
    $('uptime').textContent = [Math.floor(seconds / 3600), Math.floor(seconds / 60) % 60, seconds % 60]
      .map(value => String(value).padStart(2, '0')).join(':');
  }

  function updateStatus() {
    const wifi = state.status?.wifi;
    $('wifi-status').textContent = wifi?.captureMode === 'replay' ? 'Replay · ' + (wifi.replayState || '').toLowerCase()
      : wifi?.captureRunning ? [wifi.captureMode, wifi.captureInterface].filter(Boolean).join(' · ')
      : wifi?.captureError ? 'Capture ended' : 'Idle';
    $('wifi-status').title = wifi?.captureError || (wifi?.scopedBssidCount ? 'Scoped to ' + wifi.scopedBssidCount + ' BSSIDs' : '');
    $('wifi-dot').classList.toggle('live', !!wifi?.captureRunning);
    $('wifi-dot').classList.toggle('error', !!wifi?.captureError);
    $('wifi-total').textContent = number(state.wifi.length);
    $('probe-total').textContent = number(wifi?.probeRequests);
    const vendors = new Set(state.wifi.map(item => item.vendor));
    vendors.delete('Unknown');
    vendors.delete('Locally administered');
    $('vendor-total').textContent = number(vendors.size);
    $('ops-notice').hidden = state.status?.operationsEnabled !== false;
    for (const button of by('#ops button[type="submit"], #lan-button')) button.disabled = !state.status?.operationsEnabled || !!state.ops.active;
    for (const button of by('[data-stop]')) button.disabled = !state.status?.operationsEnabled;
    tickUptime();
  }

  function signalCell(value) {
    return element('td', signal(value), 'mono nowrap');
  }

  function wifiWithLabels() {
    const entries = [...(state.profile?.accessPoints || []), ...(state.profile?.devices || [])];
    const labels = new Map(entries.map(entry => [entry.token, entry.label]));
    return state.wifi.map(item => labels.has(item.id) ? { ...item, label: labels.get(item.id) } : item);
  }

  function networkTopology() {
    const aps = state.topology.accessPoints || [];
    const saved = state.profile?.accessPoints || [];
    if (!saved.length) return state.topology;
    const labels = new Map(saved.map(entry => [entry.token, entry.label]));
    return {
      accessPoints: aps.filter(ap => labels.has(ap.bssid)).map(ap => ({ ...ap, label: labels.get(ap.bssid) })),
      edges: (state.topology.edges || []).filter(edge => labels.has(edge.bssid))
    };
  }

  function renderPinned(devices) {
    const pins = state.profile?.devices || [];
    const seen = new Map(devices.map(device => [device.id, device]));
    $('pinned-panel').hidden = !pins.length;
    $('pinned-devices').replaceChildren(...pins.map(pin => {
      const item = seen.get(pin.token);
      const button = element('button', pin.label, 'pinned-device');
      button.type = 'button';
      button.disabled = !item;
      button.append(element('span', item ? 'Last seen ' + clock(item.last) : 'Waiting for an observation', 'caption'));
      button.addEventListener('click', () => { state.selected = item.id; renderIntel(); });
      return button;
    }));
  }

  function focusAp(now = observationNow()) {
    const topology = networkTopology();
    const aps = topology.accessPoints || [];
    if (state.apChoice === 'all') return 'all';
    if (state.apChoice && aps.some(ap => ap.bssid === state.apChoice)) return state.apChoice;
    const preferred = state.profile?.accessPoints?.find(entry => aps.some(ap => ap.bssid === entry.token))?.token
      || state.status?.wifi?.preferredApId;
    if (preferred && aps.some(ap => ap.bssid === preferred)) return preferred;
    if (!aps.some(ap => ap.bssid === state.autoAp)) {
      const counts = new Map();
      for (const edge of topology.edges || []) {
        if (timestamp(edge.lastSeen) >= now - recentMs) counts.set(edge.bssid, (counts.get(edge.bssid) || 0) + 1);
      }
      const fresh = aps.filter(ap => timestamp(ap.lastSeen) >= now - recentMs);
      const candidates = fresh.length ? fresh : [...aps];
      candidates.sort((a, b) => (counts.get(b.bssid) || 0) - (counts.get(a.bssid) || 0)
        || (b.rssiMedian ?? -128) - (a.rssiMedian ?? -128) || a.bssid.localeCompare(b.bssid));
      state.autoAp = candidates[0]?.bssid || null;
    }
    return state.autoAp;
  }

  function renderApChoices(focus) {
    const aps = networkTopology().accessPoints || [];
    const options = [['all', 'All access points'], ...aps.map(ap => [ap.bssid, window.EwaveGraph.apLabel(ap)])];
    const values = aps.length ? options : [['', 'Waiting for access points']];
    const signature = JSON.stringify(values);
    for (const id of ['intel-ap', 'map-ap']) {
      const select = $(id);
      if (select.dataset.options !== signature) {
        select.replaceChildren(...values.map(([value, label]) => {
          const option = element('option', label);
          option.value = value;
          return option;
        }));
        select.dataset.options = signature;
      }
      select.disabled = !aps.length;
      select.value = aps.length ? focus : '';
    }
  }

  function renderHiddenNetworks(accessPoints, focus) {
    const sources = { PROBE_RESP: 'Probe response', ASSOC_REQ: 'Association request', REASSOC_REQ: 'Reassociation request' };
    const hidden = accessPoints.filter(ap => ap.ssidHidden && (focus === 'all' || ap.bssid === focus));
    $('map-hidden-count').textContent = hidden.length ? number(hidden.length) + ' observed' : '';
    $('map-hidden-table').hidden = hidden.length === 0;
    $('map-hidden-empty').hidden = hidden.length > 0;
    $('map-hidden-rows').replaceChildren(...hidden.map(ap => {
      const evidence = ap.hiddenSsidEvidence;
      const nameObserved = evidence?.observedAt != null;
      return row([
        window.EwaveGraph.apLabel(ap),
        element('td', evidence?.name ?? (nameObserved ? 'Name masked' : 'Name not observed'), 'mono'),
        nameObserved ? sources[evidence.source] || 'Named management frame' : 'Hidden beacon',
        clock(evidence?.observedAt ?? evidence?.beaconObservedAt)
      ]);
    }));
  }

  function renderMap() {
    const focus = focusAp();
    renderApChoices(focus);
    const topology = networkTopology();
    renderHiddenNetworks(topology.accessPoints || [], focus);
    const wifi = wifiWithLabels();
    const outside = new Set((state.topology.edges || []).map(edge => edge.clientId));
    for (const edge of topology.edges || []) outside.delete(edge.clientId);
    window.EwaveGraph.update(topology, wifi.filter(device => !outside.has(device.id)), focus, state.selected);
    const evidence = $('map-evidence');
    const item = wifi.find(device => device.id === state.selected);
    const linked = (topology.edges || []).some(edge => edge.clientId === state.selected);
    const panel = linked || item ? linkEvidence(state.selected, item) : null;
    evidence.hidden = !panel;
    evidence.replaceChildren(...(panel ? [panel] : []));
  }

  function renderIntel() {
    const query = $('search').value.trim().toLowerCase();
    const minimum = Number($('rssi').value);
    const now = observationNow();
    const focus = focusAp(now);
    renderApChoices(focus);
    $('intel-scope').value = state.scope;
    $('intel-ap-control').hidden = state.scope !== 'network';
    const wifi = wifiWithLabels();
    renderPinned(wifi);
    const topology = networkTopology();
    const edges = topology.edges || [];
    const recent = edges.filter(edge => timestamp(edge.lastSeen) >= now - recentMs);
    const network = new Set(recent.filter(edge => focus === 'all' || edge.bssid === focus).map(edge => edge.clientId));
    for (const ap of topology.accessPoints || []) {
      if ((focus === 'all' || ap.bssid === focus) && timestamp(ap.lastSeen) >= now - recentMs) network.add(ap.bssid);
    }
    const devices = state.scope === 'network' ? wifi.filter(item => network.has(item.id)) : wifi;
    const visible = devices.filter(item => (minimum === -100 || !finite(item.rssi) || item.rssi >= minimum)
      && [item.id, item.vendor, item.type, item.label, item.details.fingerprintHint?.family]
        .some(value => String(value || '').toLowerCase().includes(query)))
      .sort((a, b) => (timestamp(b.last) || 0) - (timestamp(a.last) || 0) || a.id.localeCompare(b.id));
    const shown = visible.slice(0, state.intelLimit);
    const selected = visible.find(item => item.id === state.selected)
      || (state.profile?.devices.some(pin => pin.token === state.selected) ? wifi.find(item => item.id === state.selected) : null);
    const linked = new Set((state.topology.edges || []).map(edge => edge.clientId));
    const singles = state.wifi.filter(item => item.count === 1 && item.details?.role !== 'AP' && !linked.has(item.id)
      && timestamp(item.last) >= now - recentMs).length;
    const summary = $('feed-summary');
    summary.hidden = state.scope !== 'network';
    summary.textContent = singles + ' unassociated ' + (singles === 1 ? 'address seen once' : 'addresses seen once')
      + ' in the last 5 minutes · see All observed';
    $('device-rows').replaceChildren(...shown.map(item => {
      const address = element('td', item.id.length > 18 ? item.id.slice(0, 10) + '…' : item.id, 'mono nowrap');
      address.title = item.id;
      if (item.random) address.append(element('span', '[RND]', 'badge'));
      const vendor = element('td', item.vendor);
      if (item.label) vendor.prepend(element('strong', item.label, 'device-label'));
      const tr = row([vendor, item.type, address, signalCell(item.rssi), item.distance, clock(item.first), number(item.count)],
        () => { state.selected = item.id; renderIntel(); }, item.id === selected?.id);
      tr.classList.toggle('randomized', !!item.random);
      tr.classList.toggle('flash', Date.now() - (state.flashed.get(item.id) ?? 0) < 1400);
      return tr;
    }));
    $('feed-count').textContent = shown.length + (shown.length < visible.length ? ' of ' + visible.length : '') + ' shown';
    $('more-intel').hidden = shown.length >= visible.length;
    blank('feed-empty', visible.length === 0,
      state.scope === 'network' && !devices.length ? '◉ No recent AP or client evidence in this scope. Try All observed.'
          : devices.length ? '◉ No devices match these filters' : '◉ No device observations yet');
    renderDetail(selected);
  }

  function linkEvidence(id, item) {
    const aps = new Map((state.topology.accessPoints || []).map(ap => [ap.bssid, ap]));
    const labels = new Map((state.profile?.accessPoints || []).map(ap => [ap.token, ap.label]));
    const now = observationNow();
    const links = (state.topology.edges || []).filter(edge => edge.clientId === id
      && (edge.expiresAt == null || edge.expiresAt > now))
      .sort((a, b) => b.lastSeen - a.lastSeen || a.bssid.localeCompare(b.bssid));
    if (!links.length && (item?.details?.role === 'AP' || aps.has(id))) return null;

    const section = element('section', null, 'link-evidence');
    section.append(element('h2', 'Client link evidence'));
    if (!links.length) {
      const probes = (item?.details?.directedProbeCount || 0) + (item?.details?.wildcardProbeCount || 0);
      const probeOnly = probes > 0 && probes === item.count;
      section.append(element('strong', probeOnly ? 'Probe only' : 'No confirmed AP link', 'evidence-tag amber-text'));
      section.append(element('p', probeOnly ? 'Probe requests alone do not establish an AP link.'
        : 'No current association response or sufficient data evidence.', 'caption'));
      return section;
    }

    for (const link of links) {
      const ap = aps.get(link.bssid);
      const name = ap ? window.EwaveGraph.apLabel({ ...ap, label: labels.get(link.bssid), channel: 0 })
        : labels.get(link.bssid) || 'AP ' + link.bssid.slice(0, 8);
      const assoc = link.associationSeen != null;
      const card = element('article', null, 'link-card');
      const title = element('div', null, 'link-card-title');
      title.append(element('strong', name), element('span', assoc ? 'Association observed' : 'Data evidence',
        'evidence-tag'));
      card.append(title);
      const facts = element('dl', null, 'facts');
      const remaining = link.expiresAt == null ? null : Math.max(0, Math.ceil((link.expiresAt - now) / 1000));
      const channel = link.channel || ap?.channel;
      const freq = link.frequencyMhz ? ' · ' + link.frequencyMhz + ' MHz' : '';
      const values = [
        ['Channel', channel ? channel + freq : unavailable],
        ['Last data frame', clock(link.lastDataSeen)],
        ...(assoc ? [['Association response', clock(link.associationSeen)]] : []),
        ['Uplink / downlink', number(link.uplink) + ' / ' + number(link.downlink)],
        ['Evidence expires', remaining == null ? unavailable : clock(link.expiresAt) + ' · in '
          + Math.floor(remaining / 60) + 'm ' + (remaining % 60) + 's']
      ];
      for (const [label, value] of values) facts.append(element('dt', label), element('dd', value));
      card.append(facts);
      section.append(card);
    }
    return section;
  }

  function renderDetail(item) {
    const detail = $('device-detail');
    inspectSignalAndFingerprints(item);
    if (!item) { detail.replaceChildren(element('p', '◉ Select a device to inspect it', 'empty')); return; }
    const facts = element('dl', null, 'facts');
    const values = [
      ...(item.label ? [['Enrolled name', item.label]] : []),
      ['MAC / ID', item.id, 'mono'], ['Vendor hint', item.vendor],
      ['Role / class', item.type], [item.details.id ? 'Median RSSI' : 'RSSI', signal(item.rssi), 'mono'],
      ['Distance', item.distance], ['First seen', clock(item.first)], ['Last seen', clock(item.last)], ['Packets', number(item.count)]
    ];
    const wifi = item.details;
    if (wifi.fingerprintHint) {
      const { family, osHint, confidence } = wifi.fingerprintHint;
      values.push(['Fingerprint class hint', [family, osHint].filter(Boolean).join(' · ')
        + (finite(confidence) ? ' · score ' + confidence : '')]);
    }
    if (wifi.bands?.length) values.push(['Bands observed', wifi.bands.join(', ')]);
    if (finite(wifi.directedProbeCount)) values.push(['Directed / wildcard', wifi.directedProbeCount + ' / ' + wifi.wildcardProbeCount],
      ['WPS UUID-E', wifi.wpsUuidESeen ? 'Observed' : unavailable]);
    for (const [label, value, style] of values) facts.append(element('dt', label), element('dd', value ?? unavailable, style));
    detail.replaceChildren(facts);
    const advertised = advertisedWifi(item);
    if (advertised) detail.append(advertised);
    const evidence = linkEvidence(item.id, item);
    if (evidence) detail.append(evidence);
    const related = state.audit?.corpus?.filter(entry => entry.devices?.some(device => device.id === item.id))
      .map(entry => entry.name || entry.id) || [];
    const tags = [...new Set([...item.names, ...related])];
    detail.append(element('h2', 'Probed SSIDs'));
    const chips = element('div', null, 'chips');
    if (!tags.length) chips.append(element('span', '—', 'caption'));
    for (const value of tags) chips.append(element('span', value, 'chip'));
    detail.append(chips);
    if (state.status?.operationsEnabled) {
      const target = element('button', 'Target →');
      target.addEventListener('click', async () => {
        switchView('ops');
        await refreshTargets();
        const found = state.ops.targets.find(device => device.id === item.id || device.mac.toLowerCase() === item.id.toLowerCase());
        if (!found) {
          $('target-message').textContent = 'This device has no lab target address.';
          return;
        }
        if (item.details.role === 'AP') {
          const ap = state.ops.aps.find(entry => entry.bssid.toLowerCase() === found.mac.toLowerCase());
          if (ap) {
            $('ap-target').value = ap.bssid;
            $('handshake-channel').value = ap.channel;
            refreshChannelBadge();
          } else $('target-message').textContent = 'This access point is absent from the startup cache.';
        } else $('client-target').value = found.mac.toLowerCase();
        renderTargetChips();
      });
      detail.append(target);
    }
  }

  function advertisedWifi(item) {
    const caps = item.details.capabilities;
    const ap = (state.topology.accessPoints || []).find(ap => ap.bssid === item.id);
    if (!caps && !ap?.security) return null;
    const section = element('section', null, 'link-evidence');
    section.append(element('h2', 'Advertised Wi-Fi capabilities'));
    const facts = element('dl', null, 'facts');
    const values = [];
    if (caps) {
      const features = [[caps.sgi, 'Short GI'], [caps.ldpc, 'LDPC'], [caps.stbcTx, 'STBC TX'],
        [caps.stbcRx, 'STBC RX'], [caps.suBeamformee, 'SU beamformee'], [caps.muBeamformee, 'MU beamformee'],
        [caps.sixGhzCapability, '6 GHz capability']].filter(([seen]) => seen).map(([, name]) => name);
      values.push(['Generation', caps.wifiGeneration],
        ['Max channel width', caps.maxWidthMhz > 0 ? caps.maxWidthMhz + ' MHz' : unavailable],
        ['Spatial streams', caps.spatialStreams > 0 ? caps.spatialStreams : unavailable]);
      if (caps.supportedRates?.length) values.push(['Legacy rates', caps.supportedRates.join(', ') + ' Mbps']);
      if (features.length) values.push(['Features', features.join(', ')]);
    }
    if (ap?.advertisedSecurity?.length) {
      for (const security of ap.advertisedSecurity) {
        const suites = [
          security.authentication?.length ? 'Authentication ' + security.authentication.join(', ') : null,
          security.pairwiseCiphers?.length ? 'Pairwise ' + security.pairwiseCiphers.join(', ') : null,
          security.groupCipher ? 'Group ' + security.groupCipher : null,
          security.managementFrameProtection ? 'PMF ' + security.managementFrameProtection.toLowerCase() : null
        ].filter(Boolean);
        values.push(['Security · ' + security.protocol, suites.join(' · ') || 'Suite details unavailable']);
      }
    } else if (ap?.security) values.push(['Security', ap.security]);
    for (const [label, value] of values) facts.append(element('dt', label), element('dd', value ?? unavailable));
    section.append(facts);
    return section;
  }

  let inspection;
  function inspectSignalAndFingerprints(item) {
    $('signal-history').hidden = !item;
    const id = item?.details.id ? item.id : null;
    const enrolled = !!(id && item.label);
    $('fingerprint-form').hidden = !enrolled;
    if (!id) {
      inspection = null;
      if (item) renderSignal([]);
      return;
    }
    if (inspection?.id === id && inspection.revision === state.captureRevision && inspection.enrolled === enrolled) return;
    inspection = { id, enrolled, revision: state.captureRevision, candidates: [], loading: false, saving: false };
    $('fingerprint-form').reset();
    $('fingerprint-message').textContent = enrolled ? 'Loading observed fingerprints…' : '';
    updateFingerprintChoices([]);
    renderSignal([], 'Loading signal samples…');
    refreshInspection();
  }

  async function refreshInspection() {
    const current = inspection;
    if (!current || current.loading) return;
    current.loading = true;
    try {
      const detail = await api('/api/inventory/' + encodeURIComponent(current.id) + '/details', undefined, 404);
      if (current !== inspection || current.revision !== state.captureRevision) return;
      renderSignal(detail?.signalHistory || []);
      current.candidates = detail?.fingerprints || [];
      updateFingerprintChoices(current.candidates);
    } catch (error) {
      if (current !== inspection || current.revision !== state.captureRevision) return;
      renderSignal([], 'Signal history is unavailable.');
      current.candidates = [];
      updateFingerprintChoices([]);
    } finally {
      current.loading = false;
    }
  }

  function renderSignal(history, empty = 'No RSSI measurements captured for this address.') {
    const chart = $('signal-chart');
    const points = history.filter(sample => finite(sample.rssi) && finite(sample.timestamp)).slice(-64);
    if (!points.length) { chart.replaceChildren(element('p', empty, 'caption')); return; }
    const low = Math.floor(Math.min(...points.map(sample => sample.rssi)) / 10) * 10;
    const high = Math.max(low + 10, Math.ceil(Math.max(...points.map(sample => sample.rssi)) / 10) * 10);
    const first = points[0], last = points.at(-1);
    const min = first.timestamp, max = last.timestamp;
    const x = sample => min === max ? 164 : 8 + 312 * (sample.timestamp - min) / (max - min);
    const y = sample => 68 - 60 * (sample.rssi - low) / (high - low);
    const svgElement = (tag, attrs) => {
      const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
      for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
      return node;
    };
    const plot = svgElement('svg', { viewBox: '0 0 328 76', role: 'img',
      'aria-label': 'RSSI over time from ' + clock(min) + ' to ' + clock(max) + ', scale ' + low + ' to ' + high + ' dBm' });
    const path = points.map((sample, i) => {
      const gap = !i || sample.timestamp - points[i - 1].timestamp > 15000;
      return (gap ? 'M' : 'L') + x(sample) + ',' + y(sample);
    }).join(' ');
    plot.append(svgElement('path', { d: path, fill: 'none' }));
    for (const sample of points) plot.append(svgElement('circle', { cx: x(sample), cy: y(sample), r: 2 }));
    const scale = element('div', null, 'signal-scale caption');
    scale.append(element('span', signal(high)), element('span', signal(low)));
    const display = element('div', null, 'signal-display');
    display.append(scale, plot);
    const times = element('div', null, 'signal-times caption');
    times.append(element('span', clock(min)), element('span', clock(max)));
    chart.replaceChildren(display, times, element('p', points.length + ' samples · latest ' + signal(last.rssi), 'caption'));
  }

  const fingerprintKey = evidence => evidence.source + ':' + evidence.hash;
  const fingerprintSource = source => source.toLowerCase().replaceAll('_', ' ');
  function updateFingerprintChoices(candidates) {
    const select = $('fingerprint-choice');
    const selected = select.value;
    const options = candidates.map(evidence => {
      const option = element('option', fingerprintSource(evidence.source) + ' · ' + evidence.hash
        + ' · ' + number(evidence.observations) + ' frames');
      option.value = fingerprintKey(evidence);
      return option;
    });
    if (!options.length) options.push(element('option', 'No eligible frames in this capture'));
    select.replaceChildren(...options);
    if (candidates.some(evidence => fingerprintKey(evidence) === selected)) select.value = selected;
    select.disabled = !candidates.length || !!inspection?.saving;
    $('fingerprint-form').querySelector('button').disabled = select.disabled;
  }

  $('fingerprint-form').addEventListener('submit', async event => {
    event.preventDefault();
    const current = inspection;
    const evidence = current?.candidates.find(candidate => fingerprintKey(candidate) === $('fingerprint-choice').value);
    if (!current?.enrolled || !evidence || current.saving) return;
    current.saving = true;
    updateFingerprintChoices(current.candidates);
    try {
      await api('/api/fingerprint-samples', { observedId: current.id, hash: evidence.hash, source: evidence.source,
        family: $('fingerprint-family').value, osHint: $('fingerprint-os').value });
      if (current === inspection) $('fingerprint-message').textContent = 'Saved to Lab fingerprints.';
    } catch (error) {
      if (current === inspection) $('fingerprint-message').textContent = error.message;
    } finally {
      current.saving = false;
      if (current === inspection) updateFingerprintChoices(current.candidates);
    }
  });

  function renderFingerprintSamples(samples) {
    const list = $('fingerprint-samples');
    list.replaceChildren();
    if (!samples.length) list.append(element('p', 'No lab samples saved yet.', 'empty'));
    for (const sample of samples) {
      const card = element('article', null, 'link-card');
      const title = element('div', null, 'link-card-title');
      const remove = element('button', 'Remove');
      remove.setAttribute('aria-label', 'Remove ' + sample.family + ' sample ' + sample.evidence.hash);
      remove.addEventListener('click', () => once('fingerprint-review', async () => {
        remove.disabled = true;
        try {
          const updated = await api('/api/fingerprint-samples/' + encodeURIComponent(sample.id), undefined, undefined, 'DELETE');
          renderFingerprintSamples(updated);
        } catch (error) {
          $('sample-message').textContent = error.message;
          remove.disabled = false;
        }
      }));
      title.append(element('strong', [sample.family, sample.osHint].filter(Boolean).join(' · ')), remove);
      const { source, hash, observations, generation, maxWidthMhz, spatialStreams } = sample.evidence;
      const evidence = [fingerprintSource(source), hash, number(observations) + ' frames', generation,
        maxWidthMhz > 0 ? maxWidthMhz + ' MHz' : null, spatialStreams > 0 ? spatialStreams + ' streams' : null];
      card.append(title, element('p', evidence.filter(Boolean).join(' · '), 'caption'));
      list.append(card);
    }
  }

  $('open-fingerprint-samples').addEventListener('click', () => {
    $('fingerprint-dialog').showModal();
    once('fingerprint-review', async () => {
      $('sample-message').textContent = 'Loading lab fingerprints…';
      $('fingerprint-samples').replaceChildren();
      try {
        renderFingerprintSamples(await api('/api/fingerprint-samples'));
        $('sample-message').textContent = '';
      } catch (error) {
        $('sample-message').textContent = error.message;
      }
    });
  });

  async function refreshInventory() {
    return once('inventory', async () => {
      const revision = state.captureRevision;
      const inventory = await api('/api/inventory', undefined, 404).catch(() => undefined);
      if (revision === state.captureRevision && inventory !== undefined) {
        state.wifi = (inventory || []).map(normalizeWifi);
      }
      const now = Date.now();
      const ids = new Set(state.wifi.map(item => item.id));
      for (const id of ids) if (!state.known.has(id)) state.flashed.set(id, now);
      state.known = ids;
      for (const [id, timestamp] of state.flashed) if (now - timestamp > 1400) state.flashed.delete(id);
      updateStatus();
      renderProfileView();
    });
  }

  async function refreshStatus() {
    return once('status', async () => {
      try {
        const hadOperations = state.status?.operationsEnabled;
        state.status = await api('/api/status');
        updateStatus();
        if (state.view === 'ops' && state.status.operationsEnabled && !hadOperations) refreshTargets();
        if (state.view === 'map') renderMap();
        if (state.view === 'intel' && state.status.wifi?.captureMode === 'replay') renderIntel();
        if (state.view === 'probe') renderProbeSource();
      } catch (error) {
        $('wifi-status').textContent = 'Status unavailable';
      }
    });
  }

  async function refreshTopology() {
    return once('map', async () => {
      try {
        const revision = state.captureRevision;
        const topology = await api('/api/topology', undefined, 404) || {};
        if (revision !== state.captureRevision) return;
        state.topology = topology;
        if (state.view === 'intel') renderIntel();
        if (state.view === 'map') renderMap();
      } catch (error) {
        if (state.view === 'map') blank('graph-empty', true, '◎ ' + error.message);
      }
    });
  }

  function renderCaptureReadiness(health, scanner, scannerError) {
    const checks = $('capture-readiness-checks');
    const row = (label, result, detail, tone = '') => {
      const item = element('li');
      item.append(element('strong', label), element('span', result, tone), element('p', detail, 'caption'));
      return item;
    };
    if (health?.mode !== 'passive-rf' || !health.running) {
      const status = health?.mode === 'replay' ? 'Offline replay' : 'Live passive capture needed';
      checks.replaceChildren(row('Capture', status, 'Start a live passive Wi-Fi session to check the adapter and reception.'));
      return;
    }

    const radio = health.radio;
    const source = health.source || 'Selected adapter';
    const mode = !radio || !finite(radio.sampledAt) || Date.now() - radio.sampledAt > 15000
      ? row('Adapter mode', 'Awaiting a current radio check', source, 'amber-text')
      : radio.interfaceType === 'monitor'
        ? row('Adapter mode', 'Monitor mode', source, 'green')
        : row('Adapter mode', radio.interfaceType || 'Unknown mode', source + ' needs monitor mode.', 'amber-text');

    const age = health.sinceLastFrameMs;
    const frames = age == null
      ? row('Frame reception', 'Waiting for the first frame', 'Check the lab AP and receiver channel.', 'amber-text')
      : row('Frame reception', age < 10000 ? 'Frames arriving' : 'Capture quiet',
        'Last frame ' + (age / 1000).toFixed(1) + ' s ago · ' + number(health.decoded) + ' decoded',
        age < 10000 ? 'green' : 'amber-text');

    const telemetry = scanner?.radio;
    const tuned = (telemetry?.coverage || []).filter(entry => entry.lastTuneAtMs != null);
    const verified = tuned.filter(entry => entry.lastFrameWhileTunedAtMs != null).map(entry => entry.channel);
    let afterTune;
    if (scannerError) {
      afterTune = row('Reception after tune', 'Status unavailable', scannerError, 'amber-text');
    } else if (!scanner) {
      afterTune = row('Reception after tune', 'Fixed-channel capture', 'Use passive adaptive capture to check reception after automatic tunes.');
    } else if (!telemetry?.coverage?.length) {
      afterTune = row('Reception after tune', 'Coverage unavailable', 'Open this view during a live passive adaptive run.');
    } else if (!tuned.length) {
      afterTune = row('Reception after tune', 'Waiting for a successful tune',
        number(telemetry.failedRetunes) + ' failed tune commands in this session.', 'amber-text');
    } else if (!verified.length) {
      afterTune = row('Reception after tune', 'No reception verified yet',
        tuned.length + ' channels tuned. Check Spectrum for frame activity on those channels.', 'amber-text');
    } else {
      afterTune = row('Reception after tune', 'Verified on ' + verified.length + ' of ' + tuned.length + ' tuned channels',
        'Channels ' + verified.join(', ') + ' received frames after tuning during this session.', 'green');
    }
    checks.replaceChildren(mode, frames, afterTune);
  }

  function renderCaptureHealth(health, error = '') {
    const metrics = $('health-metrics');
    const banner = $('health-error');
    metrics.hidden = !health;
    banner.hidden = !(error || health?.error);
    banner.textContent = error || health?.error || '';
    if (!health) {
      $('health-status').textContent = 'Start monitor-mode Wi-Fi capture or replay a PCAP';
      return;
    }
    const replay = health.mode === 'replay';
    const age = health.sinceLastFrameMs;
    $('health-status').textContent = replay ? 'Replay · ' + health.replayState.toLowerCase()
      : !health.running ? 'Capture stopped' : age == null ? 'Waiting for first frame'
        : age >= 10000 ? 'Capture running · quiet' : 'Capture running';
    const fullTime = value => value == null ? unavailable : new Date(value).toLocaleString();
    const frames = Object.entries(health.frameCounts);
    const fps = Object.values(health.framesPerSecond).reduce((sum, rate) => sum + rate, 0);
    $('health-total').textContent = number(frames.reduce((sum, [, count]) => sum + count, 0));
    $('health-fps').textContent = fps.toFixed(1);
    $('health-rejects').textContent = number(health.rejected);
    $('health-drops').textContent = number(health.kernelDrops);
    $('health-drops').title = health.dropStatsAt == null ? 'Waiting for tcpdump statistics' : fullTime(health.dropStatsAt);

    const radio = health.radio;
    const tuned = radio?.channel ? radio.channel + ' · ' + radio.frequencyMhz + ' MHz' : unavailable;
    const observed = health.observedFrequencyMhz ? [health.observedChannel || null, health.observedFrequencyMhz + ' MHz']
      .filter(Boolean).join(' · ') : unavailable;
    const width = radio?.widthMhz ? radio.widthMhz + ' MHz' + (radio.widthMode ? ' (' + radio.widthMode + ')' : '') : unavailable;
    const rows = (id, values) => $(id).replaceChildren(...values.flatMap(([label, value]) =>
      [element('dt', label), element('dd', value ?? unavailable)]));
    rows('health-source', [
      [replay ? 'PCAP file' : 'Adapter', health.source],
      ...(replay ? [['Replay clock', fullTime(health.referenceTime)]]
        : [['Interface mode', radio?.interfaceType], ['Tuned channel', tuned], ['Channel width', width],
          ['Time since last frame', age == null ? unavailable : (age / 1000).toFixed(1) + ' s']]),
      ['Last decoded radio channel', observed],
      ['Last packet timestamp', fullTime(health.lastPacketAt)]
    ]);
    $('health-window').textContent = 'Last ' + health.rateWindowSeconds + (replay ? ' capture seconds' : ' seconds');
    const types = ['management', 'data', 'control', 'other', 'unclassified'];
    $('health-frames').replaceChildren(...types.map(type =>
      row([type[0].toUpperCase() + type.slice(1), number(health.frameCounts[type]),
        (health.framesPerSecond[type] || 0).toFixed(1)])));
    rows('health-decoder', [
      ['Decoded frames', number(health.decoded)], ['Unsupported frame types', number(health.unsupported)],
      ['Truncated captures', number(health.truncated)], ['Kernel stats sampled', fullTime(health.dropStatsAt)]
    ]);
  }

  async function refreshCaptureHealth() {
    return once('capture-health', async () => {
      let health;
      try { health = await api('/api/capture-health', undefined, 503); }
      catch (error) {
        renderCaptureHealth(null, error.message);
        renderCaptureReadiness(null);
        return;
      }
      renderCaptureHealth(health);
      let scanner, scannerError;
      if (health?.mode === 'passive-rf' && health.running) {
        try { scanner = await api('/api/channels', undefined, 503); }
        catch (error) { scannerError = error.message; }
      }
      renderCaptureReadiness(health, scanner, scannerError);
    });
  }

  async function refreshSpectrum() {
    return once('spectrum', async () => {
      try { window.EwaveSpectrum.update(await api('/api/channels', undefined, 503), state.status?.wifi?.channel); }
      catch (error) { window.EwaveSpectrum.update(null, null, error.message); }
    });
  }

  function isp(name) {
    if (!name) return 'Unknown';
    return [['JIO', 'Jio'], ['AIRTEL', 'Airtel'], ['BSNL', 'BSNL'], ['ACT', 'ACT Fibernet'], ['HATHWAY', 'Hathway']]
      .find(([prefix]) => name.toUpperCase().startsWith(prefix))?.[1] || 'Unknown';
  }

  function renderTimeline(values) {
    const svg = $('probe-timeline');
    const make = (tag, attrs, text) => {
      const item = document.createElementNS('http://www.w3.org/2000/svg', tag);
      for (const [name, value] of Object.entries(attrs)) item.setAttribute(name, value);
      if (text != null) item.textContent = text;
      return item;
    };
    const ticks = [0, 5, 10, 15, 20];
    const max = Math.max(1, ...values);
    const items = [make('line', { x1: 35, x2: 508, y1: 144, y2: 144, stroke: 'var(--border-bright)' }),
      make('text', { x: 5, y: 24, fill: 'var(--text-secondary)', 'font-size': 11 }, max)];
    for (const tick of ticks) {
      items.push(make('text', { x: 36 + tick * 23, y: 163, fill: 'var(--text-secondary)', 'font-size': 10,
        'text-anchor': tick === 0 ? 'start' : tick === 20 ? 'end' : 'middle' }, tick === 20 ? 'Now' : '−' + (10 - tick / 2) + 'm'));
    }
    values.forEach((value, index) => {
      const height = 118 * value / max;
      const bar = make('rect', { x: 36 + index * 23, y: 143 - height, width: 16, height, rx: 2, fill: 'var(--text-secondary)' });
      bar.append(make('title', {}, value + ' probes'));
      items.push(bar);
    });
    svg.replaceChildren(...items);
  }

  function renderProbeSource() {
    const wifi = state.status?.wifi;
    const label = wifi?.captureMode === 'replay'
      ? 'File replay' + (wifi.replayState ? ' · ' + wifi.replayState.toLowerCase() : '')
      : wifi?.captureRunning ? 'Live radio capture' : 'Current capture';
    $('probe-source-label').textContent = label;
  }

  function renderProbeFinding(audit) {
    const names = (audit?.corpus || []).flatMap(entry => entry.name ? [entry.name] : []).slice(0, 6);
    let headline, explanation;
    if (!audit) {
      headline = 'Probe data is unavailable';
      explanation = 'Open the built-in example or check Capture health for the status of your receiver.';
    } else if (audit.totalProbes === 0) {
      headline = 'No Wi-Fi requests were decoded';
      explanation = 'Open the built-in example to see what a request containing a network name looks like.';
    } else if (audit.directedProbes === 0) {
      headline = 'The requests carried no network names';
      explanation = 'ewave decoded ' + audit.totalProbes + ' general Wi-Fi '
        + (audit.totalProbes === 1 ? 'request' : 'requests') + ' asking what networks are nearby.';
    } else {
      headline = audit.directedProbes + ' of ' + audit.totalProbes + ' Wi-Fi requests included a network name';
      explanation = names.length ? 'ewave read these names directly from the captured requests.'
        : 'Names are masked in this capture. Set audit.revealSsids when launching ewave to change that.';
    }
    if ($('probe-capture-headline').textContent !== headline) $('probe-capture-headline').textContent = headline;
    if ($('probe-capture-explanation').textContent !== explanation) $('probe-capture-explanation').textContent = explanation;
    const list = $('probe-capture-names');
    list.hidden = names.length === 0;
    list.replaceChildren(...names.map(name => element('li', name, 'mono')));
  }

  function renderAudit() {
    const audit = state.audit;
    renderProbeSource();
    renderProbeFinding(audit);
    const corpus = audit?.corpus || [];
    const selected = corpus.find(entry => entry.id === state.ssid);
    const display = entry => entry.name || entry.id;
    $('audit-summary').textContent = audit ? [
      audit.totalProbes + ' probes', audit.distinctDirectedSsids + ' distinct directed SSIDs',
      audit.locallyAdministeredPct.toFixed(1) + '% locally administered',
      audit.wpsUuidEPct.toFixed(1) + '% UUID-E',
      audit.sampleLimitReached ? 'Sample limit reached' : null
    ].filter(Boolean).join('  ·  ') : '';
    $('probe-visibility').textContent = corpus.some(entry => entry.name) ? 'SSID names enabled' : 'Session-scoped SSID tokens';
    $('ssid-rows').replaceChildren(...corpus.map(entry => row([
      element('td', display(entry), 'mono'), entry.deviceCount ?? unavailable,
      clock(entry.firstSeen), clock(entry.lastSeen), isp(entry.name)
    ], () => { state.ssid = state.ssid === entry.id ? null : entry.id; renderAudit(); }, entry.id === selected?.id)));
    blank('ssid-empty', !corpus.length, audit ? '⊞ No directed probes in the audit window' : '⊞ Wi-Fi probe audit unavailable');
    const count = selected?.deviceCount;
    $('ssid-device-title').textContent = selected
      ? display(selected) + (count == null ? '' : ' · ' + count + (count === 1 ? ' observed address' : ' observed addresses'))
      : 'Addresses that probed this SSID';
    const devices = new Map(state.wifi.map(item => [item.id, item]));
    const matching = selected?.devices || [];
    $('ssid-devices').replaceChildren(...matching.map(entry => {
      const device = devices.get(entry.id);
      return row([element('td', entry.id, 'mono'), device?.vendor, signalCell(device?.rssi), clock(entry.lastSeen)]);
    }));
    blank('ssid-device-empty', !matching.length, !selected ? '⊞ Select an SSID to inspect it'
      : !audit.deviceDetailsEnabled ? '⊞ Device details require -Daudit.deviceDetails=true' : '⊞ No device observations');
    renderTimeline(selected?.timeline || audit?.timeline || []);
  }

  async function refreshAudit() {
    return once('audit', async () => {
      try {
        const revision = state.captureRevision;
        const audit = await api('/api/probe-audit', undefined, 404);
        if (revision !== state.captureRevision) return;
        state.audit = audit;
        if (state.view === 'probe') renderAudit();
        if (state.view === 'intel' && state.selected) renderDetail(wifiWithLabels().find(item => item.id === state.selected));
      } catch (error) {
        if (state.view === 'probe') {
          renderProbeFinding(null);
          blank('ssid-empty', true, '⊞ ' + error.message);
        }
      }
    });
  }

  const ops = state.ops;
  const selectedAp = () => ops.aps.find(ap => ap.bssid === $('ap-target').value);
  function options(id, items, placeholder) {
    const select = $(id), selected = select.value;
    const initial = element('option', placeholder);
    initial.value = '';
    const nodes = items.map(([value, text]) => {
      const option = element('option', text);
      option.value = value;
      return option;
    });
    select.replaceChildren(initial, ...nodes);
    if (items.some(([value]) => value === selected)) select.value = selected;
  }

  function renderTargetChips() {
    const client = $('client-target').value, ap = selectedAp();
    const chips = [];
    if (ap) chips.push(element('span', ap.ssid || ap.bssid, 'chip'));
    if (client) chips.push(element('span', client, 'chip mono'));
    $('target-chips').replaceChildren(...chips);
  }

  async function refreshChannelBadge() {
    const badge = $('ops-channel-badge');
    const ap = selectedAp();
    badge.hidden = true;
    if (!ap || ap.frequencyMhz !== 2407 + 5 * ap.channel || ap.channel < 1 || ap.channel > 13) return;
    try {
      const data = await api('/api/channels', undefined, 503);
      if (selectedAp() !== ap) return;
      const channel = data?.channels?.find(entry => entry.channel === ap.channel);
      if (!finite(channel?.score)) return;
      badge.textContent = 'Ch ' + ap.channel + ' · scanner score ' + channel.score.toFixed(2);
      badge.classList.toggle('amber-text', channel.score < .10);
      badge.hidden = false;
    } catch {
      // Scanner context is optional. The cached AP remains selectable.
    }
  }

  function renderTargets() {
    options('ap-target', ops.aps.map(ap => [ap.bssid, (ap.ssid || 'Hidden SSID') + ' · ch ' + ap.channel + ' · ' + ap.bssid]), 'Select cached AP');
    const clients = new Map();
    for (const target of [...ops.lan, ...ops.targets, ...ops.manual]) {
      clients.set(target.mac.toLowerCase(), (target.label || target.vendor || 'Manual') + ' · ' + target.mac);
    }
    options('client-target', Array.from(clients), 'None selected · broadcast / any');
    renderTargetChips();
    refreshChannelBadge();
  }

  let targetRequest;
  function refreshTargets() {
    if (!state.status?.operationsEnabled) return Promise.resolve();
    targetRequest ||= loadTargets().finally(() => { targetRequest = null; });
    return targetRequest;
  }

  async function loadTargets() {
    const results = await Promise.allSettled([api('/api/attack/aps'), api('/api/attack/targets'), api('/api/attack/scan-lan')]);
    const errors = [];
    for (const [index, key] of ['aps', 'targets', 'lan'].entries()) {
      if (results[index].status === 'fulfilled') ops[key] = results[index].value;
      else errors.push(results[index].reason.message);
    }
    $('target-message').textContent = errors.join(' · ');
    renderTargets();
  }

  function log(message, level) {
    for (const line of String(message).trim().split('\n')) {
      if (!line) continue;
      const tone = level ?? (/error|fail/i.test(line) ? 'red' : /handshake|KEY FOUND/i.test(line) ? 'green'
        : /sending|deauth/i.test(line) ? 'amber-text' : '');
      $('console').append(element('div', '[' + clock(Date.now()) + '] ' + line, tone));
    }
    while ($('console').childElementCount > 400) $('console').firstChild.remove();
    $('console').scrollTop = $('console').scrollHeight;
  }

  function operation(name) {
    for (const button of by('[data-operation]')) {
      const active = button.dataset.operation === name;
      button.classList.toggle('chosen', active);
      button.setAttribute('aria-pressed', String(active));
    }
    for (const id of ['deauth', 'handshake', 'verify']) $(id + '-form').hidden = id !== name;
  }

  function stages(index, result) {
    ops.stage = index;
    by('#handshake-stages li').forEach((item, i) => {
      item.className = i < index || (i === index && result === 'done') ? 'done' : i === index ? result : '';
    });
  }

  function stageFor(stage) {
    if (/complete/i.test(stage)) return 4;
    if (/finishing/i.test(stage)) return 3;
    if (/reconnect|handshake/i.test(stage)) return 2;
    if (/beacon/i.test(stage)) return 1;
    return 0;
  }

  async function pollOperation(name) {
    return once('ops-status', async () => {
      try {
        const path = name === 'deauth' ? '/api/attack/status' : '/api/attack/handshake/status';
        const status = await api(path);
        if (ops.active !== name || !status.running) return;
        const text = name === 'deauth' ? status.command || 'Sending deauth frames…' : status.stage;
        if (text && $(name + '-status').textContent !== text) { $(name + '-status').textContent = text; log(text); }
        if (name === 'handshake') stages(stageFor(text), 'active');
      } catch (error) {
        if (ops.active === name) $(name + '-status').textContent = 'Status unavailable · ' + error.message;
      }
    });
  }

  async function runOperation(name, path, body, finish) {
    const status = $(name + '-status');
    if (ops.active || !state.status?.operationsEnabled) return;
    ops.active = name;
    status.classList.remove('red');
    status.textContent = 'Running…';
    updateStatus();
    log('Starting ' + name);
    const timer = name !== 'verify' ? setInterval(() => pollOperation(name), 1000) : null;
    try { finish(await api(path, body)); }
    catch (error) {
      status.textContent = error.message;
      status.classList.add('red');
      if (name === 'handshake') stages(Math.max(0, ops.stage), 'failed');
      log('Error · ' + error.message);
    } finally {
      clearInterval(timer);
      ops.active = null;
      updateStatus();
    }
  }

  $('deauth-form').addEventListener('submit', event => {
    event.preventDefault();
    const ap = selectedAp();
    if (!ap) { $('deauth-status').textContent = 'Select a cached access point first.'; return; }
    runOperation('deauth', '/api/attack/deauth', {
      apBssid: ap.bssid, clientMac: $('client-target').value || null,
      count: $('deauth-count').valueAsNumber, interface: $('deauth-interface').value.trim()
    }, result => {
      const text = result.success ? 'Deauth process completed' : 'Deauth failed';
      $('deauth-status').textContent = text;
      if (result.channelWarning) log(result.channelWarning, 'amber-text');
      log(text + '\n' + (result.output || ''));
    });
  });

  $('handshake-form').addEventListener('submit', event => {
    event.preventDefault();
    const ap = selectedAp();
    if (!ap) { $('handshake-status').textContent = 'Select a cached access point first.'; return; }
    $('verify-jump').hidden = true;
    stages(0, 'active');
    runOperation('handshake', '/api/attack/handshake', {
      apBssid: ap.bssid, clientMac: $('client-target').value || null,
      interface: $('handshake-interface').value.trim(), channel: $('handshake-channel').valueAsNumber,
      frequencyMhz: ap.frequencyMhz, ssid: ap.ssid
    }, result => {
      const text = result.handshakeDetected ? 'Handshake captured' : result.outcome.replaceAll('_', ' ');
      $('handshake-status').textContent = text + (result.capFilePath ? '\n' + result.capFilePath : '');
      stages(4, result.handshakeDetected ? 'done' : 'failed');
      if (result.capFilePath) $('capture-path').value = result.capFilePath;
      $('verify-jump').hidden = !result.handshakeDetected;
      log(text + (result.captureOutput ? '\n' + result.captureOutput : ''));
    });
  });

  $('verify-form').addEventListener('submit', event => {
    event.preventDefault();
    $('psk').hidden = $('verify-details').hidden = true;
    runOperation('verify', '/api/attack/handshake/verify', {
      capFilePath: $('capture-path').value.trim(), wordlistPath: $('wordlist').value.trim()
    }, result => {
      const text = result.vulnerable ? 'KEY FOUND' : 'NOT FOUND — wordlist exhausted';
      $('verify-status').textContent = text;
      $('psk').hidden = !result.vulnerable;
      $('psk').textContent = result.vulnerable ? result.psk : '';
      $('verify-details').hidden = !result.fullOutput;
      $('verify-output').textContent = result.fullOutput || '';
      log(text);
    });
  });

  for (const button of by('[data-stop]')) button.addEventListener('click', async () => {
    try { await api('/api/attack/stop', {}); log('Stop requested'); }
    catch (error) { log('Error · ' + error.message); }
  });
  for (const tab of by('[data-operation]')) tab.addEventListener('click', () => operation(tab.dataset.operation));
  $('verify-jump').addEventListener('click', () => operation('verify'));
  $('clear-console').addEventListener('click', () => $('console').replaceChildren());
  $('manual-form').addEventListener('submit', event => {
    event.preventDefault();
    const value = $('manual-mac').value.trim().toLowerCase();
    if (!mac.test(value)) { $('target-message').textContent = 'Enter a six-octet MAC address.'; return; }
    if (!ops.manual.some(item => item.mac === value)) ops.manual.push({ mac: value });
    renderTargets();
    $('client-target').value = value;
    $('manual-mac').value = '';
    $('target-message').textContent = '';
    renderTargetChips();
  });
  $('lan-button').addEventListener('click', async () => {
    try {
      ops.lan = await api('/api/attack/scan-lan');
      renderTargets();
      $('target-message').textContent = ops.lan.length + ' cached LAN neighbors';
    } catch (error) { $('target-message').textContent = error.message; }
  });
  $('client-target').addEventListener('change', renderTargetChips);
  $('ap-target').addEventListener('change', () => {
    const ap = selectedAp();
    if (ap) $('handshake-channel').value = ap.channel;
    renderTargetChips();
    refreshChannelBadge();
  });
  function resetIntelPage() {
    state.intelLimit = intelPageSize;
    renderIntel();
  }

  $('search').addEventListener('input', resetIntelPage);
  $('rssi').addEventListener('input', () => {
    $('rssi-value').textContent = $('rssi').value === '-100' ? 'Any' : $('rssi').value + ' dBm';
    resetIntelPage();
  });
  $('more-intel').addEventListener('click', () => { state.intelLimit += intelPageSize; renderIntel(); });
  $('intel-scope').addEventListener('change', () => {
    state.scope = $('intel-scope').value;
    resetIntelPage();
  });
  $('intel-ap').addEventListener('change', () => {
    state.apChoice = $('intel-ap').value;
    resetIntelPage();
  });
  $('map-ap').addEventListener('change', () => {
    state.apChoice = $('map-ap').value;
    state.intelLimit = intelPageSize;
    renderMap();
  });
  $('reset-graph').addEventListener('click', () => {
    state.apChoice = state.autoAp = state.selected = null;
    window.EwaveGraph.reset();
    renderMap();
  });
  $('show-unassociated').addEventListener('change', renderMap);
  $('graph-wrap').addEventListener('ewave:select', event => {
    state.selected = event.detail;
    renderMap();
  });

  function nearbyAccessPoints() {
    const owned = new Set((state.profile?.accessPoints || []).map(ap => ap.token));
    const topology = new Map((state.topology.accessPoints || []).map(ap => [ap.bssid, ap]));
    return (state.profile?.observedAccessPoints || []).filter(ap => !owned.has(ap.token))
      .map(ap => {
        const details = topology.get(ap.token);
        const channel = details?.channel || ap.channel;
        return { ...ap, channel, caption: window.EwaveGraph.apLabel({ ...details, bssid: ap.token, channel }) };
      })
      .sort((a, b) => (b.rssi ?? -128) - (a.rssi ?? -128) || a.token.localeCompare(b.token));
  }

  function renderNearby() {
    const aps = nearbyAccessPoints();
    $('nearby-rows').replaceChildren(...aps.map(ap => {
      const add = element('button', 'Add to My Network');
      add.type = 'button';
      add.addEventListener('click', () => openNetwork(ap.token));
      const action = element('td');
      action.append(add);
      const entry = row([ap.caption, ap.channel || unavailable, signalCell(ap.rssi), clock(ap.lastSeen), action]);
      entry.setAttribute('role', 'row');
      for (const cell of entry.cells) cell.setAttribute('role', 'cell');
      const [name, channel, signalReading, seen] = entry.cells;
      name.classList.add('nearby-name');
      for (const [cell, label] of [[channel, 'Channel'], [signalReading, 'Signal'], [seen, 'Last seen']]) {
        const caption = element('span', label, 'nearby-field caption');
        caption.setAttribute('aria-hidden', 'true');
        cell.prepend(caption);
      }
      return entry;
    }));
    blank('nearby-empty', !aps.length, '⌁ No nearby access points heard recently');
  }

  function renderProfileView() {
    if (state.view === 'intel') renderIntel();
    if (state.view === 'map') renderMap();
    if (state.view === 'nearby') renderNearby();
  }

  async function refreshMyNetwork() {
    return once('network-profile', async () => {
      const revision = state.profileRevision;
      try {
        const profile = await api('/api/my-network');
        if (revision !== state.profileRevision || state.profileSaving) return;
        const firstLoad = !state.profile;
        state.profile = profile;
        renderProfileView();
        if (firstLoad && $('network-dialog').open) renderNetworkDialog();
      } catch (error) {
        if ($('network-dialog').open) $('network-message').textContent = error.message;
        if (state.view === 'nearby') blank('nearby-empty', true, '⌁ ' + error.message);
      }
    });
  }

  function updateApEntryMode() {
    const manual = !$('observed-ap').value;
    $('manual-ap-label').hidden = !manual;
    $('network-bssid').required = manual;
  }

  let apMatches = null;

  function renderNetworkDialog(selected = $('observed-ap').value) {
    const profile = state.profile;
    const choices = nearbyAccessPoints().filter(ap => apMatches == null || apMatches.has(ap.token));
    const observed = $('observed-ap');
    const manual = element('option', 'Enter a BSSID manually');
    manual.value = '';
    observed.replaceChildren(manual, ...choices.map(ap => {
      const option = element('option', ap.caption);
      option.value = ap.token;
      return option;
    }));
    observed.value = choices.some(ap => ap.token === selected) ? selected : '';
    updateApEntryMode();
    for (const [container, kind, entries] of [['saved-aps', 'ap', profile?.accessPoints], ['saved-devices', 'device', profile?.devices]]) {
      const list = $(container);
      list.replaceChildren(...(entries || []).map(entry => {
        const li = element('li', null, 'network-entry');
        const label = element('input');
        label.value = entry.label;
        label.maxLength = 64;
        label.setAttribute('aria-label', 'Rename ' + entry.label);
        const rename = element('button', 'Rename');
        rename.type = 'button';
        rename.addEventListener('click', () => saveMyNetwork({ action: 'save-' + kind, id: entry.id, label: label.value }));
        const remove = element('button', 'Remove');
        remove.type = 'button';
        remove.setAttribute('aria-label', 'Remove ' + entry.label);
        remove.addEventListener('click', () => saveMyNetwork({ action: 'remove-' + kind, id: entry.id }));
        li.append(label, rename, remove);
        return li;
      }));
      if (!list.childElementCount) list.append(element('li', 'Nothing saved yet', 'caption'));
    }
    $('restrict-network').checked = !!(profile?.restrictCapture || profile?.commandLineScope);
    $('restrict-network').disabled = !profile || profile.commandLineScope || !profile.accessPoints.length;
    $('network-scope-note').textContent = profile?.commandLineScope
      ? 'Capture scope for this run comes from rf.bssids.'
      : 'Changing scope clears current Wi-Fi reports. Nearby AP advertisements remain visible.';
  }

  function openNetwork(selected = '') {
    $('network-message').textContent = '';
    apMatches = null;
    $('find-network-ap').reset();
    renderNetworkDialog(selected);
    if (!$('network-dialog').open) $('network-dialog').showModal();
    refreshMyNetwork().then(() => {
      if ($('network-dialog').open && !state.profileSaving && !apMatches) renderNetworkDialog($('observed-ap').value || selected);
    });
  }

  async function saveMyNetwork(change, form) {
    if (state.profileSaving) return;
    state.profileSaving = true;
    state.profileRevision++;
    const message = $('network-message');
    message.textContent = 'Saving…';
    message.classList.remove('red');
    const old = state.profile;
    try {
      const next = await api('/api/my-network', change);
      const oldIds = (old?.accessPoints || []).map(entry => entry.id).join(',');
      const newIds = next.accessPoints.map(entry => entry.id).join(',');
      if (!next.commandLineScope && (!!old?.restrictCapture !== next.restrictCapture
          || next.restrictCapture && oldIds !== newIds)) {
        state.captureRevision++;
        state.wifi = [];
        state.topology = {};
        state.audit = null;
        state.autoAp = null;
      }
      state.profile = next;
      if (form) form.reset();
      renderNetworkDialog();
      renderProfileView();
      message.textContent = 'Saved';
      refreshInventory();
      refreshTopology();
      refreshStatus();
    } catch (error) {
      $('restrict-network').checked = !!(old?.restrictCapture || old?.commandLineScope);
      message.textContent = error.message;
      message.classList.add('red');
    } finally {
      state.profileSaving = false;
    }
  }

  for (const button of by('[data-network-setup]')) button.addEventListener('click', () => openNetwork());
  $('close-network').addEventListener('click', () => $('network-dialog').close());
  $('observed-ap').addEventListener('change', updateApEntryMode);
  $('find-network-ap').addEventListener('submit', async event => {
    event.preventDefault();
    const message = $('network-message');
    message.classList.remove('red');
    try {
      const matches = await api('/api/my-network/find', { ssid: $('find-ssid').value });
      await refreshMyNetwork();
      apMatches = new Set(matches);
      const first = nearbyAccessPoints().find(ap => apMatches.has(ap.token));
      renderNetworkDialog(first?.token || '');
      message.textContent = $('observed-ap').options.length > 1
        ? ($('observed-ap').options.length - 1) + ' matching unsaved APs. Choose a channel and save a label.'
        : 'No matching unsaved APs on the tuned channel. You can enter a BSSID manually.';
    } catch (error) {
      message.textContent = error.message;
      message.classList.add('red');
    }
  });
  $('add-network-ap').addEventListener('submit', event => {
    event.preventDefault();
    const observedId = $('observed-ap').value;
    saveMyNetwork({ action: 'save-ap', label: $('network-ap-label').value,
      ...(observedId ? { observedId } : { address: $('network-bssid').value }) }, event.currentTarget);
  });
  $('add-network-device').addEventListener('submit', event => {
    event.preventDefault();
    saveMyNetwork({ action: 'save-device', label: $('network-device-label').value,
      address: $('network-device-mac').value }, event.currentTarget);
  });
  $('restrict-network').addEventListener('change', () =>
    saveMyNetwork({ action: 'scope', restricted: $('restrict-network').checked }));
  $('all-observations').addEventListener('click', () => {
    state.scope = 'all';
    setRadio('all');
    state.intelLimit = intelPageSize;
    switchView('intel');
  });

  function switchView(name) {
    state.view = name;
    for (const view of by('.view')) view.hidden = view.id !== name;
    for (const button of by('[data-view]')) {
      button.classList.toggle('active', button.dataset.view === name);
      if (button.dataset.view === name) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    }
    if (name === 'intel') { renderIntel(); refreshTopology(); refreshInventory(); refreshAudit(); }
    if (name === 'nearby') { renderNearby(); refreshMyNetwork(); refreshInventory(); }
    if (name === 'map') { renderMap(); refreshTopology(); refreshInventory(); }
    if (name === 'health') refreshCaptureHealth();
    if (name === 'spectrum') { refreshSpectrum(); window.EwaveApWatch.refresh(); }
    if (name === 'probe') { refreshAudit(); refreshInventory(); }
    if (name === 'ops') refreshTargets();
  }

  for (const button of by('[data-view]')) button.addEventListener('click', () => switchView(button.dataset.view));
  function connect() {
    const endpoint = new URL('/ws/events', window.location.href);
    endpoint.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const socket = new WebSocket(endpoint);
    socket.onopen = () => { $('connection').hidden = true; };
    socket.onclose = () => { $('connection').hidden = false; setTimeout(connect, 3000); };
    socket.onerror = () => socket.close();
    let inventoryTimer, auditTimer;
    socket.onmessage = event => {
      let message;
      try { message = JSON.parse(event.data); } catch { return; }
      if (!message || typeof message.type !== 'string') return;
      const { type, channel, reason, deviation, deviceHint } = message;
      if (type === 'eapol_window') {
        log('Channel ' + channel + ' activity rose after deauth (' + reason
          + '). Possible reconnect. EAPOL was not verified.', 'amber-text');
        const field = $('handshake-channel');
        if (!field.value && selectedAp()?.channel === channel) field.value = channel;
      }
      if (type === 'anomaly_target' && finite(deviation)) {
        log('New activity on channel ' + channel + ' · ' + deviceHint + ' · deviation '
          + deviation.toFixed(1) + 'σ. Review cached access points on this channel.', '');
      }
      if (['WIFI_DEVICE_SEEN', 'DEVICE_APPEARED', 'DEVICE_UPDATED'].includes(type)) {
        inventoryTimer ||= setTimeout(() => { inventoryTimer = null; refreshInventory(); }, 1000);
      }
      if (['PROBE_RECEIVED', 'PROBE_REQUEST'].includes(type)) {
        auditTimer ||= setTimeout(() => { auditTimer = null; refreshAudit(); }, 1000);
      }
    };
  }

  refreshStatus();
  refreshMyNetwork();
  refreshInventory();
  refreshTopology();
  refreshAudit();
  connect();
  setInterval(refreshStatus, 3000);
  setInterval(() => { if (state.view === 'nearby' || $('network-dialog').open) refreshMyNetwork(); }, 5000);
  setInterval(() => { if (['intel', 'map', 'nearby'].includes(state.view)) refreshInventory(); }, 3000);
  setInterval(() => { if (state.view === 'intel') refreshInspection(); }, 3000);
  setInterval(() => { if (['intel', 'map'].includes(state.view)) refreshTopology(); if (state.view === 'probe') refreshAudit(); }, 5000);
  setInterval(() => {
    if (state.view === 'health') refreshCaptureHealth();
    if (state.view === 'spectrum') window.EwaveApWatch.refresh();
    if (state.view === 'spectrum' || state.status?.wifi?.captureMode === 'packets') refreshSpectrum();
  }, 2000);
  setInterval(tickUptime, 1000);
})();
