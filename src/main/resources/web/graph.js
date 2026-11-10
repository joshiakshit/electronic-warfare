'use strict';

window.EwaveGraph = (() => {
  const wrap = document.querySelector('#graph-wrap');
  const svg = document.querySelector('#topology-graph');
  const lines = svgElement('g', svg, { 'aria-hidden': 'true' });
  const labels = svgElement('g', svg, { 'aria-hidden': 'true' });
  const dots = svgElement('g', svg);
  const moreAps = document.querySelector('#more-map-aps');
  const selection = document.querySelector('#map-selection');
  const expanded = new Map();
  const clientsPerGroup = 6;
  const accessPointsPerPage = 12;
  let apLimit = accessPointsPerPage;
  let data;

  function attributes(element, values) {
    for (const [name, value] of Object.entries(values)) {
      if (value == null) element.removeAttribute(name);
      else element.setAttribute(name, value);
    }
  }

  function svgElement(tag, parent, values = {}) {
    const element = document.createElementNS('http://www.w3.org/2000/svg', tag);
    attributes(element, values);
    parent.append(element);
    return element;
  }

  // Keep existing elements so refreshing observations preserves keyboard focus.
  function renderItems(parent, items, create, update) {
    const existing = new Map(Array.from(parent.children, child => [child.dataset.key, child]));
    let next = parent.firstElementChild;
    for (const item of items) {
      const element = existing.get(item.key) || create();
      element.dataset.key = item.key;
      update(element, item);
      existing.delete(item.key);
      if (element !== next) parent.insertBefore(element, next);
      next = element.nextElementSibling;
    }
    for (const element of existing.values()) element.remove();
  }

  function apLabel(ap) {
    const name = ap.label || (ap.ssidToken ? 'SSID ' + ap.ssidToken.slice(0, 8) : ap.ssidHidden ? 'Hidden SSID' : 'AP ' + ap.bssid.slice(-6));
    return ap.channel ? name + ' · Ch ' + ap.channel : name;
  }

  function symbol(node) {
    if (node.kind === 'ap') return '■';
    if (/phone|tablet/i.test(node.type)) return '◆';
    if (/laptop|computer/i.test(node.type)) return '▲';
    return '●';
  }

  function description(node) {
    if (node.kind === 'more') return node.label;
    const signal = Number.isFinite(node.rssi) ? Math.round(node.rssi) + ' dBm' : null;
    return [node.label, node.vendor !== 'Unknown' ? node.vendor : null, node.type, signal,
      node.evidence != null ? node.evidence + ' evidence frames' : null, node.id].filter(Boolean).join(' · ');
  }

  function draw() {
    if (!data || !wrap.clientWidth) return;
    const { topology, wifi, focus, selected } = data;
    const showOther = document.querySelector('#show-unassociated').checked;
    const width = wrap.clientWidth;
    const aps = topology.accessPoints || [];
    const visibleAps = focus === 'all' ? aps.slice(0, apLimit) : aps.filter(ap => ap.bssid === focus);
    const columns = Math.max(1, Math.min(visibleAps.length, Math.floor(width / 220)));
    const devices = new Map(wifi.map(device => [device.id, device]));
    const linked = new Set();
    const edgesByAp = new Map();
    for (const edge of topology.edges || []) {
      linked.add(edge.clientId);
      if (!edgesByAp.has(edge.bssid)) edgesByAp.set(edge.bssid, []);
      edgesByAp.get(edge.bssid).push(edge);
    }
    const nodes = [], edges = [], headings = [];
    let top = 32;
    function addDevice(id, kind, x, y, extra = {}) {
      const device = devices.get(id);
      nodes.push({ id, key: kind + ':' + id, kind, x, y, vendor: device?.vendor, type: device?.type,
        rssi: device?.rssi, label: device?.label, ...extra });
    }

    for (let start = 0; start < visibleAps.length; start += columns) {
      let bottom = top;
      visibleAps.slice(start, start + columns).forEach((ap, column) => {
        const lane = width / columns;
        const center = lane * (column + .5);
        const apY = top + 20;
        addDevice(ap.bssid, 'ap', center, apY, { label: apLabel(ap), type: 'Access point', rssi: ap.rssiMedian });
        const members = (edgesByAp.get(ap.bssid) || []).sort((a, b) => a.clientId.localeCompare(b.clientId));
        const limit = expanded.get(ap.bssid) || clientsPerGroup;
        const visible = members.slice(0, limit);
        const slots = Math.min(6, Math.max(3, Math.floor((lane - 20) / 64)));
        headings.push({ key: ap.bssid, x: center, y: apY + 49, text: members.length + ' observed clients' });

        visible.forEach((edge, index) => {
          const col = index % slots;
          const row = Math.floor(index / slots);
          const inRow = Math.min(slots, visible.length - row * slots);
          const x = center + (col - (inRow - 1) / 2) * Math.min(65, (lane - 20) / slots);
          const y = apY + 100 + row * 55;
          edges.push({ key: ap.bssid + ':' + edge.clientId, x1: center, y1: apY + 55, x2: x, y2: y,
            rssi: devices.get(edge.clientId)?.rssi });
          addDevice(edge.clientId, 'client', x, y, { key: 'client:' + ap.bssid + ':' + edge.clientId,
            evidence: edge.evidenceCount });
        });

        let end = apY + 77 + Math.ceil(visible.length / slots) * 55;
        if (members.length > clientsPerGroup) {
          const remaining = members.length - visible.length;
          nodes.push({ key: 'more:' + ap.bssid, id: ap.bssid, kind: 'more', x: center, y: end,
            label: remaining ? '+' + remaining + ' clients' : 'Show fewer',
            limit: remaining ? limit + 24 : clientsPerGroup });
          end += 29;
        }
        bottom = Math.max(bottom, end);
      });
      top = bottom + 24;
    }

    function extraRows(items, kind, label) {
      if (!items.length) return;
      const limit = 24;
      const shown = items.slice(0, limit);
      headings.push({ key: kind, x: width / 2, y: top,
        text: label + (items.length > limit ? ' · showing ' + limit + ' of ' + items.length : ' · ' + items.length) });
      const slots = Math.max(1, Math.min(12, Math.floor(width / 60)));
      shown.forEach((device, index) => {
        const row = Math.floor(index / slots);
        const inRow = Math.min(slots, shown.length - row * slots);
        addDevice(device.id, kind, width / 2 + (index % slots - (inRow - 1) / 2) * 48,
          top + 29 + row * 42, device);
      });
      top += 36 + Math.ceil(shown.length / slots) * 42;
    }
    const apIds = new Set(aps.map(ap => ap.bssid));
    if (showOther) extraRows(wifi.filter(row => !apIds.has(row.id) && !linked.has(row.id) && row.details?.role !== 'AP')
      .sort((a, b) => a.id.localeCompare(b.id)), 'unassociated', 'Unassociated Wi-Fi');

    const height = Math.max(280, top);
    attributes(svg, { viewBox: `0 0 ${width} ${height}`, height });
    renderItems(lines, edges, () => svgElement('line', lines), (line, edge) => {
      attributes(line, {
        x1: edge.x1, y1: edge.y1, x2: edge.x2, y2: edge.y2,
        stroke: 'var(--text-secondary)', 'stroke-width': 1,
        'stroke-opacity': Number.isFinite(edge.rssi) ? Math.min(.8, Math.max(.22, (edge.rssi + 105) / 70)) : .35
      });
    });
    renderItems(labels, headings, () => svgElement('text', labels, {
      'text-anchor': 'middle', class: 'map-group-caption'
    }), (text, label) => {
      attributes(text, { x: label.x, y: label.y });
      text.textContent = label.text;
    });

    function activate(node) {
      if (node.kind === 'more') {
        expanded.set(node.id, node.limit);
        draw();
      } else {
        wrap.dispatchEvent(new CustomEvent('ewave:select', { detail: node.id }));
      }
    }
    renderItems(dots, nodes, () => {
      const group = svgElement('g', dots, { tabindex: 0, role: 'button', class: 'map-node' });
      svgElement('circle', group, { class: 'map-marker' });
      svgElement('rect', group, { x: -50, y: -12, width: 100, height: 24, rx: 6, class: 'map-marker' });
      svgElement('text', group, { 'text-anchor': 'middle', class: 'map-node-label' });
      svgElement('text', group, {
        class: 'map-symbol', 'text-anchor': 'middle', 'dominant-baseline': 'central', 'aria-hidden': 'true'
      });
      svgElement('title', group);
      return group;
    }, (group, node) => {
      const isMore = node.kind === 'more';
      const isSelected = node.id === selected;
      attributes(group, {
        transform: `translate(${node.x},${node.y})`,
        'aria-label': description(node),
        'aria-pressed': isMore ? null : String(isSelected)
      });
      group.onclick = () => activate(node);
      group.onkeydown = event => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          activate(node);
        }
      };
      const [circle, rect, text, marker, title] = group.children;
      attributes(circle, {
        display: isMore ? 'none' : null,
        r: node.kind === 'ap' ? 18 : 10
      });
      attributes(rect, { display: isMore ? null : 'none' });
      marker.textContent = isMore ? '' : symbol(node);
      text.setAttribute('y', isMore ? 4 : node.kind === 'ap' ? 33 : -16);
      if (node.kind === 'ap' || isMore) text.textContent = node.label;
      else text.textContent = isSelected ? (node.label || node.vendor || node.id.slice(-6)).slice(0, 16) : '';
      title.textContent = description(node);
    });
    const selectedNode = nodes.find(node => node.id === selected && node.kind !== 'more');
    selection.textContent = selectedNode ? description(selectedNode) : 'Select or hover over a node to see its details.';
    const count = nodes.filter(node => node.kind !== 'more').length;
    document.querySelector('#node-count').textContent = count + ' nodes';
    const empty = document.querySelector('#graph-empty');
    empty.hidden = count > 0;
    empty.classList.remove('loading');
    empty.textContent = aps.length ? '◎ No nodes match this focus' : '◎ Waiting for access point observations';
    moreAps.hidden = focus !== 'all' || visibleAps.length >= aps.length;
    moreAps.textContent = 'Show more APs (' + visibleAps.length + ' of ' + aps.length + ')';
  }

  moreAps.addEventListener('click', () => { apLimit += accessPointsPerPage; draw(); });
  new ResizeObserver(draw).observe(wrap);

  function update(topology, wifi, focus, selected) {
    if (data?.focus !== focus) {
      apLimit = accessPointsPerPage;
      expanded.clear();
    }
    data = { topology, wifi, focus, selected };
    draw();
  }

  function reset() {
    expanded.clear();
    apLimit = accessPointsPerPage;
  }

  return { update, apLabel, reset };
})();
