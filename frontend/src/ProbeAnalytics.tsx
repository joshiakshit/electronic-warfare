import type { Json } from './api';
import { probeExposureLabel } from './observations';

const number = new Intl.NumberFormat();
const percent = new Intl.NumberFormat(undefined, { style: 'percent', maximumFractionDigits: 1 });
const time = new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit', second: '2-digit' });
const exposureCategories = ['PERSONAL_NAME_PATTERN', 'ROUTER_DEFAULT_PATTERN', 'CORPORATE', 'OTHER', 'SHORT_SSID_HASH'];
const networksPerAddress = ['0', '1', '2-3', '4-9', '10+'];
const bucketMs = 30_000;

function count(value: unknown) {
  return typeof value === 'number' ? number.format(value) : '—';
}

function percentage(value: unknown) {
  return typeof value === 'number' ? percent.format(value / 100) : '—';
}

function ProbeActivity({ timeline, start }: { timeline?: number[]; start?: number }) {
  if (typeof start !== 'number' || !timeline?.length) return <p className="probe-muted">Activity unavailable</p>;
  const max = Math.max(1, ...timeline);
  return (
    <>
      <ol className="channel-bars probe-bars" aria-label="Probe requests per 30-second interval">
        {timeline.map((value, index) => {
          const observedAt = time.format(start + index * bucketMs);
          const label = `${observedAt} · ${count(value)} ${value === 1 ? 'probe' : 'probes'}`;
          return (
            <li key={index} aria-label={label} title={label}>
              <span className="channel-track" aria-hidden="true">
                <span className={value ? 'channel-fill' : 'channel-fill zero'} style={{ height: `${100 * value / max}%` }} />
              </span>
            </li>
          );
        })}
      </ol>
      <div className="probe-time-range"><span>{time.format(start)}</span><span>{time.format(start + (timeline.length - 1) * bucketMs)}</span></div>
    </>
  );
}

export function ProbeAnalytics({ data }: { data: Json }) {
  const local = data.locallyAdministeredPct;
  const p2pNames = Object.entries((data.p2pDeviceNames ?? {}) as Record<string, string>);
  return (
    <section className="probe-analytics" aria-label="De-cloaker privacy and de-randomization">
      <dl className="probe-metrics">
        <div><dt>Probe requests</dt><dd className="probe-stat">{count(data.totalProbes)}</dd></div>
        <div><dt>Directed / Short-SSID</dt><dd className="probe-stat">{count(data.directedProbes)}</dd></div>
        <div><dt>Distinct networks</dt><dd className="probe-stat">{count(data.distinctDirectedSsids)}</dd></div>
        <div>
          <dt>Randomized MACs</dt>
          <dd className="probe-stat">{percentage(local)}</dd>
          <dd className="probe-muted">Locally administered · {percentage(typeof local === 'number' && data.totalObservedAddresses > 0 ? 100 - local : undefined)} globally administered</dd>
        </div>
        <div>
          <dt>Signature collapse</dt>
          <dd className="probe-stat">{count(data.totalObservedAddresses)} → {count(data.distinctSignaturesAmongLocalAddresses)}</dd>
          <dd className="probe-muted">Observed addresses → local IE cohorts</dd>
          <dd>{count(data.correlatedClusterCount)} correlated clusters</dd>
        </div>
        <div>
          <dt>Side-channel leaks</dt>
          <dd>{percentage(data.wpsUuidEPct)} WPS UUID-E · {percentage(data.passpointPct)} Passpoint</dd>
          <dd className="probe-muted">{count(data.distinctWpsUuids)} distinct UUIDs · {count(data.wpsMultiAddressCount)} across MACs</dd>
          <dd>{count(data.p2pNamedProbes)} probes with P2P device names</dd>
        </div>
      </dl>
      <div className="probe-charts">
        <section aria-label="10-Minute Probe Activity">
          <h3>10-Minute Probe Activity</h3>
          <ProbeActivity timeline={data.timeline} start={data.timelineStart} />
          {data.sampleLimitReached && <p className="probe-muted">Sample limit reached. Older probes were evicted.</p>}
        </section>
        <section aria-label="Exposure Category Breakdown">
          <h3>Exposure Category Breakdown</h3>
          <dl className="probe-counts">
            {exposureCategories.map(category => (
              <div key={category}><dt>{probeExposureLabel(category)}</dt><dd>{count(data.ssidExposureCounts?.[category])}</dd></div>
            ))}
          </dl>
        </section>
        <section aria-label="PNL Chattiness Histogram">
          <h3>PNL Chattiness Histogram</h3>
          <dl className="probe-counts" aria-label="Addresses by distinct networks probed">
            {networksPerAddress.map(bucket => (
              <div key={bucket}><dt>{bucket} {bucket === '1' ? 'network' : 'networks'}</dt><dd>{count(data.directedPerAddress?.[bucket])}</dd></div>
            ))}
          </dl>
        </section>
      </div>
      {p2pNames.length > 0 && (
        <details className="probe-names">
          <summary>P2P device names by sender</summary>
          <dl className="probe-counts">
            {p2pNames.map(([id, name]) => <div key={id}><dt><code>{id}</code></dt><dd>{name}</dd></div>)}
          </dl>
        </details>
      )}
    </section>
  );
}
