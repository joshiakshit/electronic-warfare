import { useState } from 'react';
import { send, type DeviceProfileDetail, type FingerprintObservation, type SignalSample } from './api';
import { chronologicalSignal, date, frameName } from './observations';

export function ProfilerEvidence({ detail, observedId }: { detail: DeviceProfileDetail; observedId: string }) {
  const signal = chronologicalSignal(detail.signalHistory ?? []);
  const fingerprints = detail.fingerprints ?? [];
  return (
    <>
      <section className="evidence-group" aria-label="Signal history">
        <h3>Signal history</h3>
        {signal.length > 0 ? <SignalHistory samples={signal} />
          : <p className="evidence-empty">No retained signal samples.</p>}
      </section>
      <section className="evidence-group" aria-label="Fingerprint observations">
        <h3>Fingerprint observations</h3>
        {fingerprints.length > 0 ? (
          <ul className="fingerprint-list">
            {fingerprints.map(fingerprint => (
              <li key={`${fingerprint.source}:${fingerprint.hash}`}>
                <h4>{frameName(fingerprint.source)}</h4>
                <span>{fingerprint.observations} {fingerprint.observations === 1 ? 'observation' : 'observations'}</span>
                <div className="fingerprint-capabilities">
                  {[
                    fingerprint.generation && fingerprint.generation !== 'Unknown' ? fingerprint.generation : null,
                    fingerprint.maxWidthMhz ? `${fingerprint.maxWidthMhz} MHz` : null,
                    fingerprint.spatialStreams ? `${fingerprint.spatialStreams} spatial streams` : null,
                  ].filter(Boolean).join(' · ')}
                </div>
                <code title={fingerprint.hash}>{fingerprint.hash}</code>
                <SaveFingerprint observedId={observedId} observation={fingerprint} />
              </li>
            ))}
          </ul>
        ) : <p className="evidence-empty">No retained fingerprint observations.</p>}
      </section>
    </>
  );
}

function SaveFingerprint({ observedId, observation }: { observedId: string; observation: FingerprintObservation }) {
  const [open, setOpen] = useState(false);
  const [family, setFamily] = useState('');
  const [osHint, setOsHint] = useState('');
  const [pending, setPending] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState('');

  async function save() {
    if (pending || !family.trim()) return;
    setPending(true);
    setError('');
    try {
      await send('/api/profiler/fingerprints', 'POST', {
        observedId, hash: observation.hash, source: observation.source, family: family.trim(), osHint: osHint.trim(),
      });
      setSaved(true);
      setOpen(false);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Could not save the sample');
    } finally {
      setPending(false);
    }
  }

  return open ? (
    <form className="capture-control-form fingerprint-sample-form" onSubmit={event => { event.preventDefault(); void save(); }}>
      <label>Device class<input value={family} onChange={event => setFamily(event.target.value)} maxLength={64} required /></label>
      <label>OS hint (optional)<input value={osHint} onChange={event => setOsHint(event.target.value)} maxLength={64} /></label>
      <button type="submit" disabled={pending || !family.trim()}>Save sample</button>
      <button type="button" className="text-button" disabled={pending} onClick={() => setOpen(false)}>Cancel</button>
      {error && <p className="inline-error" role="alert">{error}</p>}
    </form>
  ) : (
    <div className="fingerprint-sample-form">
      <button type="button" className="text-button" onClick={() => { setOpen(true); setSaved(false); }}>Save as sample</button>
      {saved && <span className="micro-note" role="status">Sample saved in My Network.</span>}
    </div>
  );
}

function SignalHistory({ samples }: { samples: SignalSample[] }) {
  const first = samples[0];
  const last = samples[samples.length - 1];
  const duration = last.timestamp - first.timestamp;
  const minimum = Math.min(...samples.map(sample => sample.rssi));
  const maximum = Math.max(...samples.map(sample => sample.rssi));
  const bottom = Math.floor(minimum / 5) * 5;
  const top = Math.max(bottom + 5, Math.ceil(maximum / 5) * 5);

  return (
    <>
      <figure className="signal-history" aria-label="Signal history chart">
        <figcaption>Latest sample <strong>{last.rssi} dBm</strong></figcaption>
        <div className="signal-chart" aria-hidden="true">
          <div className="signal-y-axis mono"><span>{top}</span><span>{bottom}</span></div>
          <div className="signal-plot">
            {samples.map(({ timestamp, rssi }, index) => (
              <span key={`${timestamp}-${index}`} className="signal-point"
                    style={{ left: `${duration ? 100 * (timestamp - first.timestamp) / duration : 50}%`,
                             top: `${100 * (top - rssi) / (top - bottom)}%` }}
                    title={`${date(timestamp)} · ${rssi} dBm`} />
            ))}
          </div>
          <div className="signal-x-axis"><span>{date(first.timestamp, true)}</span>{duration > 0 && <span>{date(last.timestamp, true)}</span>}</div>
        </div>
      </figure>
      <details className="signal-samples">
        <summary>Signal samples ({samples.length})</summary>
        <div className="table-wrap">
          <table aria-label="Signal samples">
            <thead><tr><th scope="col">Observed at</th><th scope="col">Signal</th></tr></thead>
            <tbody>
              {samples.map(({ timestamp, rssi }, index) => (
                <tr key={`${timestamp}-${index}`}>
                  <td><time dateTime={new Date(timestamp).toISOString()} title={date(timestamp)}>{date(timestamp, true)}</time></td>
                  <td>{rssi} dBm</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </>
  );
}
