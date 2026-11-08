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

  function heat() {
    const grid = node('div', '', 'heat-grid');
    const end = Math.floor(Date.now() / 2000);
    for (let band = 0; band < 13; band++) {
      grid.append(node('span', band + 1, 'caption'));
      for (let bucket = end - 29; bucket <= end; bucket++) {
        const value = samples.get(bucket)?.[band];
        const cell = node('span', '', 'heat-cell');
        if (Number.isFinite(value)) {
          cell.style.background = 'color-mix(in srgb, var(--accent-blue) ' + Math.round(12 + 88 * Math.min(1, Math.max(0, value))) + '%, var(--bg-elevated))';
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
      row.append(node('td', index + 1), node('td', period * 100, 'mono'));
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
    if (!document.querySelector('#spectrum').hidden) draw();
  }

  return { update };
})();
