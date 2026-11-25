import { ArrowUpRight } from 'lucide-react';
import type { CaptureHealth, CaptureStatus, TopologyReport } from './api';
import { date, observationKey, observationValue, roamApLabel } from './observations';

export function Overview({ status, health, topology, probes, onNavigate }: {
  probes?: number; status?: CaptureStatus; health?: CaptureHealth | null;
  topology?: TopologyReport | null; onNavigate: (id: string) => void;
}) {
  const recent = (topology?.roams ?? []).slice().sort((a, b) => b.time - a.time).slice(0, 5);
  const aps = new Map(topology?.accessPoints?.map(ap => [ap.bssid, ap]));
  const counts = [
    { label: 'Decoded frames', value: health?.decoded, target: 'capture-health' },
    { label: 'Probe requests', value: probes ?? (status?.wifi.captureMode === 'idle' ? undefined : status?.wifi.probeRequests), target: 'de-cloaker' },
    { label: 'Observed access points', value: topology?.accessPoints?.length, target: 'inspector' },
    { label: 'Confirmed client links', value: topology?.edges.length, target: 'spotter' },
  ];

  return (
    <>
      <div className="overview-counts">
        {counts.map(({ label, value, target }) => (
          <button type="button" className="overview-count" onClick={() => onNavigate(target)} key={target}
                  aria-label={`${label}, ${value ?? 'unavailable'}`}>
            <span className="count-label">{label}<ArrowUpRight size={14} aria-hidden="true" /></span>
            <strong>{value?.toLocaleString() ?? '—'}</strong>
          </button>
        ))}
      </div>
      <section className="overview-activity" aria-labelledby="recent-ap-changes">
        <div className="overview-activity-header">
          <h2 id="recent-ap-changes">Recent AP changes</h2>
          {recent.length > 0 && (
            <button type="button" className="text-button" onClick={() => onNavigate('tracker')}>
              View Tracker <ArrowUpRight size={13} aria-hidden="true" />
            </button>
          )}
        </div>
        {recent.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">Client</th><th scope="col">From AP</th><th scope="col">To AP</th>
                  <th scope="col">Evidence method</th><th scope="col">Observed at</th>
                </tr>
              </thead>
              <tbody>
                {recent.map(item => (
                  <tr key={observationKey('roams', item)}>
                    <td className="mono">{item.clientId}</td>
                    <td><span className="roam-ap">{roamApLabel(aps.get(item.fromBssid), item.fromChannel, item.fromBand)}<code>{item.fromBssid}</code></span></td>
                    <td><span className="roam-ap">{roamApLabel(aps.get(item.toBssid), item.toChannel, item.toBand)}<code>{item.toBssid}</code></span></td>
                    <td>{observationValue('method', item)}</td>
                    <td className="mono" title={date(item.time)}>{date(item.time, true)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="overview-empty">
            {topology ? 'No AP changes observed.' : topology === null ? 'AP changes unavailable.' : 'Loading AP changes…'}
          </p>
        )}
      </section>
    </>
  );
}
