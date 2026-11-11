'use strict';

(() => {
  const byId = id => document.getElementById(id);
  const captureButton = byId('probe-capture-source');
  const replayButton = byId('probe-demo-source');
  const capture = byId('probe-capture');
  const replay = byId('probe-demo');
  const status = byId('probe-demo-status');
  const evidence = byId('probe-demo-evidence');

  function showReplay(active) {
    capture.hidden = active;
    replay.hidden = !active;
    captureButton.classList.toggle('chosen', !active);
    replayButton.classList.toggle('chosen', active);
    captureButton.setAttribute('aria-pressed', String(!active));
    replayButton.setAttribute('aria-pressed', String(active));
  }

  captureButton.addEventListener('click', () => showReplay(false));
  replayButton.addEventListener('click', async () => {
    showReplay(true);
    if (!evidence.hidden) return;
    replayButton.disabled = true;
    status.textContent = 'Decoding synthetic probe requests…';
    try {
      const response = await fetch('/api/probe-audit/demo');
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const observations = await response.json();
      const named = observations.find(observation => observation.networkName);
      byId('probe-demo-headline').textContent = 'A device asked for “' + named.networkName + '”';
      byId('probe-demo-explanation').textContent = 'ewave read the network name directly from a Wi-Fi request on channel '
        + named.channel + '. The other request carried no network name.';
      byId('probe-demo-rows').replaceChildren(...observations.map(({ elapsedMs, channel, networkName }) => {
        const row = document.createElement('tr');
        for (const text of [elapsedMs + ' ms', channel, networkName ? 'Named probe' : 'General probe',
          networkName ?? 'No name in request']) {
          const cell = document.createElement('td');
          cell.textContent = text;
          row.append(cell);
        }
        return row;
      }));
      byId('probe-demo-finding').hidden = false;
      evidence.hidden = false;
      status.textContent = 'Built-in example · two synthetic Wi-Fi requests';
    } catch {
      status.textContent = 'Example unavailable. Select Built-in example to try again.';
    } finally {
      replayButton.disabled = false;
    }
  });

  byId('probe-compare').addEventListener('click', () => {
    const spectrum = document.querySelector('[data-view="spectrum"]');
    spectrum.click();
    spectrum.focus();
    byId('run-scanner-demo').click();
  });

  function openFromLink() {
    const example = location.hash === '#probe-demo';
    if (!example && location.hash !== '#probe') return;
    document.querySelector('[data-view="probe"]').click();
    (example ? replayButton : captureButton).click();
  }

  document.addEventListener('DOMContentLoaded', openFromLink);
  window.addEventListener('hashchange', openFromLink);
})();
