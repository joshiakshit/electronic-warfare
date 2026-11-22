import { useEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from 'react';
import { LockKeyhole, Search, X } from 'lucide-react';
import { get, type AdvertisedSecurity, type ApChange, type DeviceProfileDetail, type Json } from './api';
import {
  channelBand, date, groupApChanges, isIdentifier, isTimestamp, observationColumns, observationKey,
  observationLabel, observationValue, occupancyEstimate, occupancyLabel, primaryEvidence, short,
} from './observations';
import { ProfilerEvidence } from './ProfilerEvidence';
import { startSnapshotPolling } from './snapshotPolling';

export function ObservationReport({ kind, rows, running, stale, emptyMessage = 'No observations recorded' }: {
  kind: string; rows: Json[]; running: boolean; stale: boolean; emptyMessage?: string;
}) {
  const [query, setQuery] = useState('');
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const rowButtons = useRef(new Map<string, HTMLButtonElement>());
  const filter = useRef<HTMLInputElement>(null);
  const evidenceHeading = useRef<HTMLHeadingElement>(null);
  const focusEvidence = useRef(false);
  const columns = useMemo(() => observationColumns(kind, rows), [kind, rows]);
  const search = query.trim().toLowerCase();
  const visible = useMemo(() => rows.filter(row => (
    !search || JSON.stringify(row).toLowerCase().includes(search)
    || columns.some(key => observationValue(key, row, true).toLowerCase().includes(search))
  )), [columns, rows, search]);
  const groups = useMemo<{ clientId: string | null; rows: Json[] }[]>(() => kind === 'roams'
    ? groupApChanges(visible as ApChange[])
    : [{ clientId: null, rows: visible }], [kind, visible]);
  const selected = visible.find(row => observationKey(kind, row) === selectedKey);

  useEffect(() => {
    if (focusEvidence.current && selectedKey !== null) {
      evidenceHeading.current?.focus();
      focusEvidence.current = false;
    }
  }, [selectedKey]);

  function closeEvidence() {
    const trigger = selectedKey === null ? null : rowButtons.current.get(selectedKey);
    setSelectedKey(null);
    (trigger ?? filter.current)?.focus({ preventScroll: true });
  }

  function selectChannel(key: string) {
    setSelectedKey(key);
    const button = rowButtons.current.get(key);
    button?.focus({ preventScroll: true });
    button?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }

  return (
    <div onKeyDown={event => {
      if (event.key === 'Escape' && selected) {
        event.preventDefault();
        closeEvidence();
      }
    }}>
      <div className="table-tools">
        <div className="result-count">
          {visible.length} {visible.length === 1 ? 'result' : 'results'}
          {search && rows.length !== visible.length && ` of ${rows.length}`}
          {kind === 'roams' && visible.length > 0 && ' · Oldest first per client'}
          {stale && ' · Last successful report'}
        </div>
        <label className="search">
          <Search size={14} aria-hidden="true" />
          <input
            ref={filter}
            value={query}
            onChange={event => {
              setQuery(event.target.value);
              setSelectedKey(null);
            }}
            placeholder="Filter results"
            aria-label="Filter results"
          />
        </label>
      </div>
      {kind === 'channels' && visible.length > 0 && (
        <ChannelChart channels={visible} selectedKey={selectedKey} onSelect={selectChannel} />
      )}
      {visible.length > 0 ? (
        <div className={selected ? 'report-layout has-evidence' : 'report-layout'}>
          <div className={`table-wrap report-table report-table-${kind}`}>
            <table>
              <thead>
                <tr>{columns.map(key => <th key={key} scope="col">{observationLabel(kind, key)}</th>)}</tr>
              </thead>
              {groups.map(group => (
               <tbody key={group.clientId ?? 'report'}>
                {group.clientId && (
                  <tr className="report-group">
                    <th colSpan={columns.length} scope="rowgroup">
                      <span>Client <code>{group.clientId}</code></span>
                      <span>{group.rows.length} {group.rows.length === 1 ? 'change' : 'changes'}</span>
                    </th>
                  </tr>
                )}
                {group.rows.map(row => {
                  const rowKey = observationKey(kind, row);
                  const isSelected = selectedKey === rowKey;
                  return (
                    <tr key={rowKey} className={isSelected ? 'is-selected' : undefined} onClick={() => setSelectedKey(rowKey)}>
                      {columns.map((key, columnIndex) => {
                        const value = observationValue(key, row, true);
                        const isMasked = key === 'name' && !row.name;
                        return (
                          <td key={key} className={isTimestamp(key) || isIdentifier(key) ? 'mono' : undefined}
                              title={isTimestamp(key) ? date(row[key]) : value}>
                            {columnIndex === 0 ? (
                              <button
                                type="button"
                                className={isMasked ? 'row-subject masked-name' : 'row-subject'}
                                ref={node => {
                                  if (node) rowButtons.current.set(rowKey, node);
                                  else rowButtons.current.delete(rowKey);
                                }}
                                aria-expanded={isSelected}
                                aria-controls={isSelected ? 'observation-evidence' : undefined}
                                onClick={event => {
                                  event.stopPropagation();
                                  if (isSelected) closeEvidence();
                                  else {
                                    focusEvidence.current = event.detail === 0;
                                    setSelectedKey(rowKey);
                                  }
                                }}
                              >
                                {isMasked && <LockKeyhole size={12} aria-hidden="true" />}
                                <span>{value}</span>
                                {kind === 'hidden' && row.bssid && <code title={row.bssid}>{row.bssid}</code>}
                              </button>
                            ) : key === 'nameStatus' ? (
                              <span className={row.nameStatus === 'Name observed' ? 'name-status observed' : 'name-status'}>{value}</span>
                            ) : value}
                          </td>
                        );
                      })}
                    </tr>
                  );
                })}
               </tbody>
              ))}
            </table>
          </div>
          {selected && (
            <Evidence key={selectedKey} kind={kind} row={selected} subjectKey={columns[0]}
                      headingRef={evidenceHeading} onClose={closeEvidence} />
          )}
        </div>
      ) : (
        <div className="report-empty">
          <strong>{rows.length ? 'No matching results' : emptyMessage}</strong>
          {(rows.length > 0 || running) && <span>{rows.length ? 'Try a different filter.' : 'Waiting for captured traffic.'}</span>}
        </div>
      )}
    </div>
  );
}

function ChannelChart({ channels, selectedKey, onSelect }: {
  channels: Json[]; selectedKey: string | null; onSelect: (key: string) => void;
}) {
  const bands = new Map<string, Json[]>();
  for (const channel of [...channels].sort((a, b) => a.freqMhz - b.freqMhz)) {
    const band = channelBand(channel.freqMhz);
    const group = bands.get(band);
    if (group) group.push(channel);
    else bands.set(band, [channel]);
  }

  return (
    <section className="channel-chart" aria-labelledby="channel-chart-title">
      <div className="channel-chart-header">
        <h2 id="channel-chart-title">Estimated occupancy</h2>
        <span>Scanner estimate · 0–100% · — unavailable</span>
      </div>
      {[...bands].map(([band, rows]) => (
        <div className="channel-band" key={band}>
          <h3>{band}</h3>
          <div className="channel-bars">
            {rows.map(row => {
              const key = observationKey('channels', row);
              const estimate = occupancyEstimate(row);
              const label = occupancyLabel(row);
              return (
                <button
                  key={key}
                  type="button"
                  className="channel-bar"
                  aria-label={`${band}, channel ${row.channel}, ${label}`}
                  aria-pressed={selectedKey === key}
                  onClick={() => onSelect(key)}
                  title={label}
                >
                  <span className="channel-value" aria-hidden="true">{estimate === null ? '—' : label}</span>
                  <span className="channel-track" aria-hidden="true">
                    {estimate !== null && (
                      <span className={estimate === 0 ? 'channel-fill zero' : 'channel-fill'}
                            style={{ height: `${estimate * 100}%` }} />
                    )}
                  </span>
                  <span className="channel-number mono" aria-hidden="true">{row.channel}</span>
                </button>
              );
            })}
          </div>
        </div>
      ))}
    </section>
  );
}

function Evidence({ kind, row, subjectKey, headingRef, onClose }: {
  kind: string; row: Json; subjectKey: string; headingRef: RefObject<HTMLHeadingElement>; onClose: () => void;
}) {
  const [detail, setDetail] = useState<DeviceProfileDetail | null>(null);
  const [error, setError] = useState('');
  const profileId = kind === 'inventory' ? row.id : null;
  useEffect(() => {
    if (!profileId) return;
    const endpoint = `/api/profiler/${encodeURIComponent(profileId)}`;
    const poll = startSnapshotPolling(async signal => {
      try {
        const value = await get<DeviceProfileDetail>(endpoint, signal);
        if (signal.aborted) return;
        setDetail(value);
        setError('');
      } catch (failure) {
        if (signal.aborted) return;
        setDetail(null);
        setError(failure instanceof Error ? failure.message : 'Backend unavailable');
      }
    }, 4000);
    return poll.stop;
  }, [profileId]);

  const evidence: Json = { ...row, ...detail };
  const priority = primaryEvidence(kind, evidence);
  const classificationFields = ['classLabel', 'classConfidence', 'osHint'];
  // Preserve the original fields for inspection, including the probe report ID and timeline.
  const advanced = Object.keys(evidence).filter(key => (
    key !== subjectKey && (!priority.includes(key) || (evidence[key] && typeof evidence[key] === 'object')
      || (kind === 'aps' && ['security', 'channelUtilization'].includes(key)))
  ));
  return (
    <aside className="evidence" id="observation-evidence" aria-label="Observation evidence">
      <header>
        <div>
          <span className="evidence-caption">Evidence</span>
          <h2 ref={headingRef} tabIndex={-1}>{observationValue(subjectKey, row)}</h2>
        </div>
        <button type="button" className="icon-btn" onClick={onClose} aria-label="Close evidence">
          <X size={18} />
        </button>
      </header>
      {kind === 'aps' && <AccessPointEvidence row={evidence} priority={priority} />}
      {kind === 'inventory' ? (
        <EvidenceFields kind={kind} fields={priority.filter(key => classificationFields.includes(key))} row={evidence} />
      ) : kind !== 'aps' && <EvidenceFields kind={kind} fields={priority} row={evidence} />}
      {profileId && !detail && !error && <p className="micro-note" role="status">Loading fingerprint and signal details…</p>}
      {error && <p className="inline-error" role="status">Additional device detail unavailable. {error}</p>}
      {detail && profileId && <ProfilerEvidence detail={detail} observedId={profileId} />}
      {kind === 'inventory' && priority.some(key => !classificationFields.includes(key)) && (
        <section className="evidence-group" aria-label="Device observations">
          <h3>Device observations</h3>
          <EvidenceFields kind={kind} fields={priority.filter(key => !classificationFields.includes(key))} row={evidence} />
        </section>
      )}
      {advanced.length > 0 && (
        <details className="evidence-raw">
          <summary>Raw fields</summary>
          <EvidenceFields kind={kind} fields={advanced} row={evidence} raw />
        </details>
      )}
    </aside>
  );
}

function AccessPointEvidence({ row, priority }: { row: Json; priority: string[] }) {
  const profiles: AdvertisedSecurity[] = row.advertisedSecurity ?? [];
  const loadFields: readonly string[] = ['stationCount', 'channelUtilization'];
  const load = priority.filter(key => loadFields.includes(key));
  const observed = priority.filter(key => key !== 'security' && !loadFields.includes(key));
  return (
    <>
      <section className="evidence-group" aria-label="Advertised security">
        <h3>Advertised security</h3>
        {profiles.length > 0 ? profiles.map((profile, index) => (
          <div className="security-profile" key={`${profile.protocol}-${index}`}>
            <h4>{profile.protocol}</h4>
            <dl>
              <div><dt>Authentication</dt><dd>{short(profile.authentication?.join(', '))}</dd></div>
              <div><dt>Pairwise ciphers</dt><dd>{short(profile.pairwiseCiphers?.join(', '))}</dd></div>
              <div><dt>Group cipher</dt><dd>{short(profile.groupCipher)}</dd></div>
              <div><dt>Management frame protection</dt><dd>{short(profile.managementFrameProtection)}</dd></div>
            </dl>
          </div>
        )) : <p className="security-summary">{row.security || 'Security details unavailable'}</p>}
      </section>
      {load.length > 0 && (
        <section className="evidence-group" aria-label="AP-reported load">
          <h3>AP-reported load</h3>
          <EvidenceFields kind="aps" fields={load} row={row} />
        </section>
      )}
      <section className="evidence-group" aria-label="Observation">
        <h3>Observation</h3>
        <EvidenceFields kind="aps" fields={observed} row={row} />
      </section>
    </>
  );
}

function EvidenceFields({ kind, fields, row, raw = false }: { kind: string; fields: string[]; row: Json; raw?: boolean }) {
  return (
    <dl>
      {fields.map(key => {
        const value = row[key];
        let display: ReactNode = observationValue(key, row);
        if (raw) {
          display = value !== null && typeof value === 'object'
            ? <pre>{JSON.stringify(value, null, 2)}</pre>
            : short(value);
        } else if (isTimestamp(key) && typeof value === 'number' && value > 0) {
          const timestamp = new Date(value);
          display = (
            <time dateTime={timestamp.toISOString()}>
              <span>{timestamp.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })}</span>
              <span>{timestamp.toLocaleTimeString()}</span>
            </time>
          );
        }
        return (
          <div key={key}>
            <dt>{observationLabel(kind, key)}</dt>
            <dd className={isTimestamp(key) || isIdentifier(key) ? 'mono' : undefined}>
              {display}
            </dd>
          </div>
        );
      })}
    </dl>
  );
}
