import { useState } from 'react';
import { send, type DeviceProfileContext, type DeviceProfileDetail, type FingerprintObservation, type ProbeCorrelation, type SignalSample } from './api';
import { associatedApLabel, chronologicalSignal, classificationBasisLabel, date, frameName } from './observations';
import { RadioFrameEvidence } from './FrameEvidence';

export function ProfilerEvidence({ detail, observedId }: { detail: DeviceProfileDetail; observedId: string }) {
  const signal = chronologicalSignal(detail.signalHistory ?? []);
  const fingerprints = detail.fingerprints ?? [];
  return (
    <>
      <ProfilerContext context={detail} />
      {detail.inferredCorrelation && <CorrelationEvidence cluster={detail.inferredCorrelation} />}
      <RadioFrameEvidence observation={detail.radioObservation} />
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
                {(fingerprint.ieOrder?.length || fingerprint.vendorElements?.length || fingerprint.bandCohort) ? (
                  <dl className="fingerprint-fields">
                    {!!fingerprint.ieOrder?.length && <div><dt>IE tag order</dt><dd>{fingerprint.ieOrder.join(', ')}</dd></div>}
                    {!!fingerprint.vendorElements?.length && (
                      <div><dt>Vendor elements</dt><dd>{fingerprint.vendorElements.join(', ')}</dd></div>
                    )}
                    {fingerprint.bandCohort && <div><dt>Band-invariant cohort</dt><dd><code>{fingerprint.bandCohort}</code></dd></div>}
                  </dl>
                ) : null}
                <SaveFingerprint observedId={observedId} observation={fingerprint} />
              </li>
            ))}
          </ul>
        ) : <p className="evidence-empty">No retained fingerprint observations.</p>}
      </section>
    </>
  );
}

export function ProfilerContext({ context }: { context: DeviceProfileContext }) {
  const { associatedAp, osHint, classificationBasis, inferredGeneration, inferredStreams, inferredWidthMhz } = context;
  const basis = classificationBasisLabel(classificationBasis);
  if (!osHint && !basis && !associatedAp && !inferredGeneration) return null;
  return <dl className="profiler-context">
    {osHint && <div><dt>OS hint</dt><dd>{osHint}</dd></div>}
    {basis && <div><dt>Classification basis</dt><dd>{basis}</dd></div>}
    {associatedAp && <div><dt>Connection</dt><dd>{associatedApLabel(associatedAp)}</dd></div>}
    {inferredGeneration && <div><dt>Observed PHY</dt><dd>{[
      inferredGeneration,
      inferredWidthMhz ? `${inferredWidthMhz} MHz` : null,
      inferredStreams ? `${inferredStreams} streams` : null,
    ].filter(Boolean).join(' · ')}</dd></div>}
  </dl>;
}

function CorrelationEvidence({ cluster }: { cluster: ProbeCorrelation }) {
  const score = new Intl.NumberFormat(undefined, { style: 'percent', maximumFractionDigits: 0 });
  return <section className="evidence-group" aria-label="Probabilistic inferred correlation">
    <h3>Probabilistic inferred correlation</h3>
    <dl>
      <div><dt>Cluster ID</dt><dd><code>{cluster.id}</code></dd></div>
      <div><dt>Heuristic confidence</dt><dd>{score.format(cluster.confidence)}</dd></div>
      <div><dt>Observed device IDs</dt><dd>{cluster.memberIds.map(id => <div key={id}><code>{id}</code></div>)}</dd></div>
    </dl>
    <details className="signal-samples">
      <summary>Probe transitions ({cluster.evidence.length})</summary>
      <ul className="fingerprint-list">
        {cluster.evidence.map(edge => {
          const basisLabels: Record<string, string> = {
            PROBE_TO_ASSOC: 'Probe-to-association capability & SSID match',
            PNL_PROFILE: 'Preferred-network list & IE fingerprint match',
            WPS_UUID_E: 'Identical WPS Enrollee UUID (UUID-E) across MACs',
          };
          const basis = edge.basis ?? '';
          const basisLabel = basisLabels[basis] ?? `Matching IE fingerprint · sequence advanced by ${edge.sequenceStep}`;
          return <li key={`${edge.fromId}-${edge.toId}-${basis}`}>
            <code>{edge.fromId} → {edge.toId}</code>
            <div>{basisLabel} · {edge.gapMs} ms apart</div>
            <div>{basis !== 'WPS_UUID_E' && `${edge.sharedDirectedSsidCount} shared directed SSID${edge.sharedDirectedSsidCount === 1 ? '' : 's'} · `}{score.format(edge.confidence)} confidence</div>
          </li>;
        })}
      </ul>
    </details>
  </section>;
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
