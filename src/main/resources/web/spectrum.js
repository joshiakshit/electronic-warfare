'use strict';

window.EwaveSpectrum = (() => {
  const chart = document.querySelector('#channel-chart');
  const empty = document.querySelector('#spectrum-empty');
  const updated = document.querySelector('#spectrum-updated');
  const bars = document.querySelector('#channel-bars');
  const periods = document.querySelector('#period-rows');
  const periodEmpty = document.querySelector('#period-empty');
  const heatmap = document.querySelector('#heatmap');
  const coupled = document.querySelector('#coupled');
  const samples = new Map();
  let selected, snapshot, lastTick;

  const node = (tag, content, className) => {
    const element = document.createElement(tag);
    element.textContent = content;
    if (className) element.className = className;
    return element;
  };

  const demoButton = document.querySelector('#run-scanner-demo');
  const demoStatus = document.querySelector('#scanner-demo-status');
  const demoResults = document.querySelector('#scanner-demo-results');
  const radio = document.querySelector('#scanner-radio');
  const seconds = ms => (ms / 1000).toFixed(2) + ' s';

  function tableRow(label, ...values) {
    const row = node('tr', '');
    const header = node('th', label);
    header.scope = 'row';
    row.append(header, ...values.map(value => node('td', value)));
    return row;
  }

  function dwellItems(adaptive, fixed) {
    return adaptive.flatMap((duration, index) => {
      if (!duration && !fixed?.[index]) return [];
      const item = node('div', '', 'scanner-dwell-item');
      item.append(node('strong', 'Ch ' + (index + 1)));
      item.append(node('span', fixed ? 'Adaptive ' + seconds(duration) : seconds(duration), 'caption mono'));
      if (fixed) item.append(node('span', 'Fixed ' + seconds(fixed[index]), 'caption mono'));
      return [item];
    });
  }

  demoButton.addEventListener('click', async () => {
    demoButton.disabled = true;
    demoStatus.textContent = 'Running scripted comparison…';
    demoResults.hidden = true;
    try {
      const response = await fetch('/api/channels/demo');
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const { durationMs, tickMs, fixedChannel, simulatedRetuneMs, frameIntervalMs, bursts, adaptive, fixed } =
        await response.json();
      demoStatus.textContent = 'Simulated RF · ' + seconds(durationMs) + ' · ' + tickMs + ' ms ticks · fixed channel '
        + fixedChannel + ' · ' + simulatedRetuneMs + ' ms per channel change · frames every ' + frameIntervalMs + ' ms during each burst';
      const retune = run => run.meanRetuneMs == null ? '—' : run.meanRetuneMs + ' ms';
      document.querySelector('#scanner-demo-totals').replaceChildren(
        tableRow('Channels visited', adaptive.channelsVisited, fixed.channelsVisited),
        tableRow('Channel changes', adaptive.retunes, fixed.retunes),
        tableRow('Mean simulated retune', retune(adaptive), retune(fixed)),
        tableRow('Frames captured', adaptive.capturedFrames, fixed.capturedFrames),
        tableRow('Frames missed', adaptive.missedFrames, fixed.missedFrames));
      const detection = event => (event.delayMs == null ? 'Missed burst' : event.delayMs + ' ms')
        + ' · ' + event.capturedFrames + '/' + (event.capturedFrames + event.missedFrames) + ' frames';
      document.querySelector('#scanner-demo-events').replaceChildren(...bursts.map((burst, index) =>
        tableRow('Ch ' + burst.channel + ' · ' + seconds(burst.startMs) + '–' + seconds(burst.endMs),
          detection(adaptive.detections[index]), detection(fixed.detections[index]))));
      document.querySelector('#scanner-demo-dwell').replaceChildren(...dwellItems(adaptive.dwellMs, fixed.dwellMs));
      demoResults.hidden = false;
    } catch {
      demoStatus.textContent = 'Comparison unavailable. Try again.';
    } finally {
      demoButton.disabled = false;
    }
  });

  function drawCoverage(telemetry) {
    const coverage = telemetry?.coverage || [];
    const showCoverage = coverage.length > 0;
    document.querySelector('#scanner-coverage').hidden = !showCoverage;
    document.querySelector('#scanner-radio-dwell-panel').hidden = showCoverage;
    if (!showCoverage) {
      const dwell = telemetry ? dwellItems(telemetry.dwellMs) : [];
      document.querySelector('#scanner-radio-dwell').replaceChildren(...dwell);
      return;
    }

    const now = Date.now();
    const timestamp = (cell, value, fallback) => {
      if (value == null) {
        cell.textContent = fallback;
        return;
      }
      const date = new Date(value);
      const age = Math.max(0, Math.floor((now - value) / 1000));
      const time = node('time', age < 1 ? 'Just now' : age + ' s ago', 'mono');
      time.dateTime = date.toISOString();
      time.title = date.toLocaleString();
      cell.append(time);
    };

    document.querySelector('#scanner-coverage-rows').replaceChildren(...coverage.map(entry => {
      const { channel, lastTuneAtMs, lastFrameAtMs, lastFrameWhileTunedAtMs } = entry;
      const row = tableRow('Ch ' + channel, seconds(telemetry.dwellMs[channel - 1]), '', '', '');
      timestamp(row.cells[2], lastTuneAtMs, 'No tune yet');
      timestamp(row.cells[3], lastFrameAtMs, 'No frame yet');
      const status = row.cells[4];
      if (lastTuneAtMs == null) {
        status.textContent = 'Awaiting tune';
      } else if (lastFrameWhileTunedAtMs == null || lastFrameWhileTunedAtMs < lastTuneAtMs) {
        status.textContent = 'No frame since tune';
        status.classList.add('amber-text');
      } else {
        status.textContent = 'Frame received';
      }
      return row;
    }));
  }

  function drawRadio() {
    radio.hidden = !snapshot;
    if (!snapshot) return;
    const telemetry = snapshot.radio;
    const channel = value => value == null ? 'Unknown' : 'Channel ' + value;
    const facts = [
      ['Scanner choice', channel(snapshot.lastChosen)],
      ['Confirmed tune', channel(telemetry?.lastConfirmedChannel) + (telemetry?.retuning ? ' · retuning' : '')],
      ['Last frame’s radio channel', channel(telemetry?.lastObservedChannel)],
      ['Retune commands', telemetry ? telemetry.successfulRetunes + ' succeeded · ' + telemetry.failedRetunes + ' failed' : 'Unavailable'],
      ['Mean successful command time', telemetry?.meanRetuneMs == null ? '—' : telemetry.meanRetuneMs.toFixed(1) + ' ms']
    ];
    document.querySelector('#scanner-radio-facts').replaceChildren(...facts.flatMap(([label, value]) =>
      [node('dt', label), node('dd', value, 'mono')]));
    drawCoverage(telemetry);
    const reasons = {
      NEW_ACTIVITY: 'Activity after a quiet baseline',
      UNUSUAL_BURST: 'Activity above the recent baseline',
      PERIOD_BROKEN: 'Previously fitted period no longer detected'
    };
    const alerts = (snapshot.channels || []).filter(entry => entry.anomaly).map(({ channel, anomaly }) =>
      node('li', 'Ch ' + channel + ' · ' + (reasons[anomaly.reason] || anomaly.reason), 'amber-text'));
    document.querySelector('#scanner-alerts').replaceChildren(...(alerts.length ? alerts : [node('li', 'No active alerts', 'caption')]));
  }

  function heat() {
    const grid = node('div', '', 'heat-grid');
    const end = Math.floor(Date.now() / 2000);
    for (let band = 0; band < 13; band++) {
      grid.append(node('span', band + 1, 'caption'));
      for (let bucket = end - 29; bucket <= end; bucket++) {
        const value = samples.get(bucket)?.[band];
        const cell = node('span', '', 'heat-cell');
        if (Number.isFinite(value)) {
          cell.style.background = 'color-mix(in srgb, var(--accent-green) ' + Math.round(12 + 88 * Math.min(1, Math.max(0, value))) + '%, var(--bg-elevated))';
          cell.title = 'Channel ' + (band + 1) + ' · occupancy ' + value.toFixed(3);
        }
        grid.append(cell);
      }
    }
    const axis = node('div', '', 'heat-axis caption');
    axis.append(node('span', '−60s'), node('span', '−30s'), node('span', 'Now'));
    heatmap.replaceChildren(grid, axis);
  }

  function draw() {
    if (!snapshot) return;
    const scores = snapshot.scores.slice(0, 13);
    const max = Math.max(0.001, ...scores);
    bars.replaceChildren(...scores.map((score, index) => {
      const channel = index + 1;
      const button = node('button', '');
      button.type = 'button';
      button.setAttribute('aria-pressed', String(channel === selected));
      const track = node('span', '', 'bar-track');
      const fill = node('i', '', 'channel-fill');
      fill.style.height = Math.max(1, score / max * 100) + '%';
      fill.classList.toggle('high', score / max >= .65);
      fill.classList.toggle('selected', channel === selected);
      track.append(fill);
      button.append(track, node('strong', channel), node('span', score.toFixed(3), 'caption mono'));
      button.addEventListener('click', () => { selected = channel; draw(); bars.children[index]?.focus(); });
      return button;
    }));
    const members = snapshot.coupledMembers.filter(index => index >= 0 && index < 13);
    coupled.replaceChildren();
    if (members.length > 1) {
      const bracket = node('span', 'Coupled ' + members.map(index => index + 1).join(' / '), 'bracket');
      bracket.style.gridColumn = (Math.min(...members) + 1) + ' / ' + (Math.max(...members) + 2);
      coupled.append(bracket);
    }
    periods.replaceChildren(...snapshot.periods.slice(0, 13).flatMap((period, index) => {
      if (!period) return [];
      const row = node('tr', '');
      row.append(node('td', index + 1), node('td', period * (snapshot.tickMs ?? 100), 'mono'));
      const uncertainty = node('td', '±' + snapshot.spreads[index].toFixed(3), 'mono');
      uncertainty.title = 'Posterior spread at the current phase. Smaller values indicate lower uncertainty.';
      row.append(uncertainty, node('td', snapshot.counts[index], 'mono'));
      return [row];
    }));
    periodEmpty.hidden = periods.childElementCount > 0;
    heat();
  }

  function update(value, channel, message) {
    snapshot = value;
    empty.classList.remove('loading');
    empty.hidden = !!value;
    empty.textContent = '≋ ' + (message || 'Summary scanner not active');
    chart.hidden = !value;
    if (!value) {
      radio.hidden = true;
      updated.textContent = '';
      periods.replaceChildren();
      periodEmpty.hidden = false;
      heatmap.replaceChildren();
      samples.clear();
      lastTick = undefined;
      return;
    }
    if (selected === undefined && channel >= 1 && channel <= 13) selected = channel;
    const now = Date.now();
    const bucket = Math.floor(now / 2000);
    if (lastTick !== undefined && value.tick < lastTick) samples.clear();
    if (value.tick !== lastTick) samples.set(bucket, value.means);
    lastTick = value.tick;
    for (const key of samples.keys()) if (key < bucket - 29) samples.delete(key);
    updated.textContent = 'Updated ' + new Date(now).toLocaleTimeString();
    if (!document.querySelector('#spectrum').hidden) {
      drawRadio();
      draw();
    }
  }

  return { update };
})();
