'use strict';

window.EwaveApWatch = (() => {
  const byId = id => document.getElementById('ap-watch-' + id);
  const choice = byId('choice');
  const find = byId('find');
  const start = byId('start');
  const stop = byId('stop');
  const save = byId('save');
  const timeline = byId('timeline');
  const gap = byId('gap');
  const status = byId('status');
  const storageKey = 'ewave.ap-watch.runs.v1';
  const endpoint = '/api/channels/watch';
  const aliases = new Map();
  let state = { available: false };
  let busy = false;
  let refreshPending;
  let saved = [];

  try {
    const entries = JSON.parse(localStorage.getItem(storageKey) || '[]');
    if (Array.isArray(entries)) saved = entries.filter(entry => entry?.run?.id).slice(0, 10);
  } catch { /* A watch works without browser storage. */ }

  function node(tag, text, className) {
    const el = document.createElement(tag);
    el.textContent = text;
    if (className) el.className = className;
    return el;
  }

  async function request(url, method = 'GET', body) {
    const options = { method, cache: 'no-store' };
    if (body) {
      options.headers = { 'Content-Type': 'application/json' };
      options.body = JSON.stringify(body);
    }
    const response = await fetch(url, options);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Watch request failed.');
    return data;
  }

  const time = timestamp => new Date(timestamp).toLocaleTimeString(undefined, { fractionalSecondDigits: 3,
    hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const seconds = milliseconds => (milliseconds / 1000).toFixed(2) + ' s';
  const label = id => aliases.get(id) || 'AP ' + id.slice(-6);
  const mode = run => run.adaptive ? 'Adaptive' : 'Fixed';
  const active = () => !!state.run && state.run.endedAt == null;

  function renderSaved() {
    byId('saved').hidden = !saved.length;
    byId('saved-rows').replaceChildren(...saved.map(({ run, name }) => {
      const row = node('tr', '');
      const origin = run.lastHeard ? 'Ch ' + run.lastHeard.channel : 'No AP frame';
      const move = run.heardAgain ? origin + ' → ' + run.heardAgain.channel : origin + ' · no move observed';
      const elapsed = run.lastHeard
        ? seconds((run.heardAgain?.timestamp ?? run.endedAt) - run.lastHeard.timestamp) + (run.heardAgain ? '' : ' until stopped')
        : '—';
      row.append(...[name, mode(run), move, elapsed].map(value => node('td', value)));
      return row;
    }));
  }

  function render() {
    const run = state.run;
    const watching = active();
    const available = state.available && !watching && !busy;
    find.querySelector('button').disabled = !available;
    byId('name').disabled = !available;
    start.querySelector('[type="submit"]').disabled = !available || !choice.value;
    choice.disabled = !available;
    stop.hidden = !watching;
    stop.disabled = busy;
    save.hidden = !run || watching;
    save.disabled = busy || saved.some(entry => entry.run.id === run?.id);
    save.textContent = save.disabled && !busy ? 'Saved' : 'Save run';

    const message = !run
      ? state.available ? 'Select an AP, then wait for a fresh frame before moving it.' : 'Start live passive Wi-Fi capture to watch an access point.'
      : mode(run) + ' · ' + label(run.apId) + ' · ' + (watching
        ? run.lastHeard ? 'Watching for a channel move' : 'Waiting for a fresh AP frame'
        : run.heardAgain ? 'AP heard again' : 'Stopped without an observed channel move');
    if (status.textContent !== message) status.textContent = message;
    timeline.hidden = !run?.lastHeard;
    gap.hidden = !run?.lastHeard;
    if (!run?.lastHeard) return;
    const events = [
      [watching ? 'Most recent AP frame' : 'Last heard', run.lastHeard, ''],
      ['Tune confirmed on new channel', run.tuned, run.adaptive ? 'Awaiting a move' : 'Fixed listener']
    ];
    if (run.heardAgain) events[1][2] = run.adaptive ? 'No confirmation in this interval' : 'Fixed listener';
    else if (!watching && run.adaptive) events[1][2] = 'No move observed';
    events.push(['First heard on new channel', run.heardAgain, watching ? 'Waiting' : 'No move observed']);
    timeline.replaceChildren(...events.map(([title, event, empty]) => {
      const item = node('li', '');
      item.append(node('strong', title),
        node('span', event ? 'Ch ' + event.channel + ' · ' + time(event.timestamp) : empty, 'caption mono'));
      return item;
    }));
    gap.textContent = run.heardAgain
      ? 'Observation gap ' + seconds(run.heardAgain.timestamp - run.lastHeard.timestamp)
        + '. This interval can include time spent changing the router’s channel.'
      : watching ? 'Move the lab AP when you’re ready.'
        : 'Watch ended ' + seconds(run.endedAt - run.lastHeard.timestamp) + ' after the last AP frame.';
  }

  async function loadOptions() {
    const profile = await request('/api/my-network');
    for (const ap of profile.accessPoints || []) {
      if (ap.token && !aliases.has(ap.token)) aliases.set(ap.token, ap.label);
    }
    const aps = (profile.observedAccessPoints || []).filter(ap => ap.channel >= 1 && ap.channel <= 13);
    const next = aps.map(ap => [ap.token, label(ap.token) + ' · Ch ' + ap.channel]);
    const current = Array.from(choice.options).slice(1).map(option => [option.value, option.textContent]);
    if (JSON.stringify(current) !== JSON.stringify(next) && document.activeElement !== choice) {
      const selected = choice.value;
      const placeholder = node('option', 'Select an access point');
      placeholder.value = '';
      choice.replaceChildren(placeholder, ...next.map(([value, text]) => {
        const option = node('option', text);
        option.value = value;
        return option;
      }));
      if (next.some(([value]) => value === selected)) choice.value = selected;
    }
  }

  async function update(action) {
    if (busy) return;
    busy = true;
    render();
    let error;
    try {
      await refreshPending;
      await action();
    } catch (failure) { error = failure.message; }
    finally {
      busy = false;
      render();
      if (error) status.textContent = error;
    }
  }

  function refresh() {
    if (busy || refreshPending) return refreshPending;
    let error;
    refreshPending = (async () => {
      state = await request(endpoint);
      if (state.available && !active()) await loadOptions();
    })().catch(failure => { error = failure.message; }).finally(() => {
      refreshPending = null;
      if (!busy) {
        render();
        if (error) status.textContent = error;
      }
    });
    return refreshPending;
  }

  find.addEventListener('submit', event => {
    event.preventDefault();
    update(async () => {
      const ssid = byId('name').value.trim();
      const ids = await request('/api/my-network/find', 'POST', { ssid });
      for (const id of ids) aliases.set(id, ssid);
      await loadOptions();
      const match = Array.from(choice.options).find(option => ids.includes(option.value));
      if (!match) throw new Error('No observed 2.4 GHz access point matches that name.');
      choice.value = match.value;
    });
  });
  start.addEventListener('submit', event => {
    event.preventDefault();
    const apId = choice.value;
    update(async () => { state = await request(endpoint, 'POST', { apId }); });
  });
  choice.addEventListener('change', render);
  stop.addEventListener('click', () => {
    const id = state.run.id;
    update(async () => { state = await request(endpoint + '/' + id, 'DELETE'); });
  });
  save.addEventListener('click', () => {
    const run = state.run;
    const next = [{ run, name: label(run.apId) }, ...saved].slice(0, 10);
    try {
      localStorage.setItem(storageKey, JSON.stringify(next));
      saved = next;
      renderSaved();
      render();
    } catch {
      status.textContent = 'Could not save this run in browser storage.';
    }
  });

  renderSaved();
  return { refresh };
})();
