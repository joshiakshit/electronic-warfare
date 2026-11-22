import { useEffect, useRef, useState } from 'react';
import { get, send, type FingerprintSample, type Json, type MyNetwork, type NamedNetworkEntry } from './api';
import { frameName } from './observations';
import { startSnapshotPolling } from './snapshotPolling';

type EntryKind = 'ap' | 'device';

export function MyNetworkSettings({ profile, onChanged }: {
  profile: MyNetwork; onChanged: (profile: MyNetwork) => void;
}) {
  const [kind, setKind] = useState<EntryKind>('ap');
  const [editing, setEditing] = useState<string | null>(null);
  const [confirmRemoval, setConfirmRemoval] = useState<string | null>(null);
  const [label, setLabel] = useState('');
  const [address, setAddress] = useState('');
  const [observedId, setObservedId] = useState('');
  const [search, setSearch] = useState('');
  const [matched, setMatched] = useState<string[] | null>(null);
  const [pending, setPending] = useState(false);
  const [feedback, setFeedback] = useState('');
  const [error, setError] = useState('');
  const options = profile.observedAccessPoints.filter(ap => matched === null || matched.includes(ap.token));
  const selectedObservedId = options.some(ap => ap.token === observedId) ? observedId : '';

  function resetForm(nextKind = kind) {
    setKind(nextKind);
    setEditing(null);
    setLabel('');
    setAddress('');
    setObservedId('');
  }

  async function change(body: Json, message: string): Promise<boolean> {
    if (pending) return false;
    setPending(true);
    setFeedback('');
    setError('');
    try {
      onChanged(await send<MyNetwork>('/api/profiler/network', 'POST', body));
      setFeedback(message);
      return true;
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'My Network update failed');
      return false;
    } finally {
      setPending(false);
    }
  }

  async function findObservedName() {
    setPending(true);
    setError('');
    try {
      const result = await send<string[]>('/api/profiler/network/find', 'POST', { ssid: search });
      setMatched(result);
      setObservedId('');
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Could not find access points');
    } finally {
      setPending(false);
    }
  }

  function entries(group: EntryKind, rows: NamedNetworkEntry[]) {
    const title = group === 'ap' ? 'Enrolled access points' : 'Enrolled devices';
    return (
      <div className="network-entry-group">
        <h3>{title}</h3>
        {rows.length === 0 ? <p className="micro-note">None enrolled</p> : (
          <ul className="network-list" aria-label={title}>
            {rows.map(entry => (
              <li key={entry.id}>
                <span>{entry.label}{entry.token && <code>{entry.token}</code>}</span>
                {confirmRemoval === entry.id ? (
                  <div className="session-inline-actions">
                    <button type="button" className="text-button" disabled={pending} onClick={async () => {
                      if (await change({ action: `remove-${group}`, id: entry.id }, 'Enrollment removed.')) {
                        setConfirmRemoval(null);
                        if (editing === entry.id) resetForm();
                      }
                    }}>Confirm removal</button>
                    <button type="button" className="text-button" onClick={() => setConfirmRemoval(null)}>Cancel</button>
                  </div>
                ) : (
                  <div className="session-inline-actions">
                    <button type="button" className="text-button" disabled={pending} onClick={() => {
                      resetForm(group);
                      setEditing(entry.id);
                      setLabel(entry.label);
                    }}>Rename</button>
                    <button type="button" className="text-button" disabled={pending} onClick={() => setConfirmRemoval(entry.id)}>Remove</button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    );
  }

  return (
    <>
      <section className="session-controls" aria-labelledby="my-network-heading">
        <div className="session-controls-heading"><h2 id="my-network-heading">My Network</h2></div>
        <div className="network-scope">
          <div>
            <strong>Capture scope</strong>
            <p className="micro-note">{profile.commandLineScope ? 'Set by the launch configuration.'
              : profile.restrictCapture ? 'Limited to enrolled access points.' : 'All observed access points.'}</p>
          </div>
          {!profile.commandLineScope && (
            <button type="button" className="session-secondary" disabled={pending || (!profile.restrictCapture && !profile.accessPoints.length)}
              onClick={() => change({ action: 'scope', restricted: !profile.restrictCapture }, 'Capture scope updated.')}>
              {profile.restrictCapture ? 'Allow all access points' : 'Restrict to enrolled access points'}
            </button>
          )}
        </div>
        {!profile.commandLineScope && <p className="micro-note">Changing capture scope clears the current session’s observations.</p>}

        <div className="network-entry-grid">{entries('ap', profile.accessPoints)}{entries('device', profile.devices)}</div>
        <h3>{editing ? 'Rename enrollment' : 'Enroll a device or access point'}</h3>
        {!editing && kind === 'ap' && profile.observedAccessPoints.length > 0 && (
          <form className="capture-control-form network-search" onSubmit={event => { event.preventDefault(); if (search) void findObservedName(); }}>
            <label>Exact observed network name<input value={search} onChange={event => setSearch(event.target.value)} maxLength={32} /></label>
            <button type="submit" className="session-secondary" disabled={!search || pending}>Find</button>
            {matched !== null && <button type="button" className="text-button" onClick={() => setMatched(null)}>Show all observed APs</button>}
            {matched?.length === 0 && <span className="micro-note">No matching access points</span>}
          </form>
        )}
        <form className="capture-control-form" onSubmit={async event => {
          event.preventDefault();
          if (await change({
            action: `save-${kind}`, label: label.trim(),
            ...(editing ? { id: editing } : selectedObservedId ? { observedId: selectedObservedId } : { address: address.trim() }),
          }, editing ? 'Enrollment renamed.' : 'Enrollment saved.')) resetForm();
        }}>
          {!editing && <label>Enrollment type<select value={kind} onChange={event => resetForm(event.target.value as EntryKind)}>
            <option value="ap">Access point</option><option value="device">Device</option>
          </select></label>}
          {!editing && kind === 'ap' && options.length > 0 && (
            <label>Observed access point<select value={selectedObservedId} onChange={event => setObservedId(event.target.value)}>
              <option value="">Enter address manually</option>
              {options.map(ap => <option value={ap.token} key={ap.token}>{ap.ssid || 'Name unavailable'} · {ap.token}</option>)}
            </select></label>
          )}
          {!editing && !selectedObservedId && <label>{kind === 'ap' ? 'BSSID' : 'MAC address'}<input value={address}
            onChange={event => setAddress(event.target.value)} placeholder="00:11:22:33:44:55" maxLength={17} required /></label>}
          <label>Label<input value={label} onChange={event => setLabel(event.target.value)} maxLength={64} required /></label>
          <button type="submit" disabled={pending || !label.trim() || (!editing && !selectedObservedId && !address.trim())}>Save enrollment</button>
          {editing && <button type="button" className="text-button" onClick={() => resetForm()}>Cancel</button>}
        </form>
        {feedback && <p className="micro-note" role="status">{feedback}</p>}
        {error && <p className="inline-error" role="alert">{error}</p>}
      </section>
      <SavedFingerprintSamples />
    </>
  );
}

const samplesPath = '/api/profiler/fingerprints';

function SavedFingerprintSamples() {
  const [samples, setSamples] = useState<FingerprintSample[]>();
  const [confirmation, setConfirmation] = useState<string | null>(null);
  const [loadError, setLoadError] = useState('');
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);
  const sampleRevision = useRef(0);
  useEffect(() => {
    const poll = startSnapshotPolling(async signal => {
      const revision = sampleRevision.current;
      try {
        const next = await get<FingerprintSample[]>(samplesPath, signal);
        if (signal.aborted || revision !== sampleRevision.current) return;
        setSamples(next);
        setLoadError('');
      } catch (failure) {
        if (signal.aborted || revision !== sampleRevision.current) return;
        setLoadError(failure instanceof Error ? failure.message : 'Could not load fingerprint samples');
      }
    }, 4000);
    return poll.stop;
  }, []);

  async function remove(id: string) {
    sampleRevision.current++;
    setPending(true);
    setError('');
    try {
      setSamples(await send<FingerprintSample[]>(`${samplesPath}/${encodeURIComponent(id)}`, 'DELETE'));
      setConfirmation(null);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Could not remove the sample');
    } finally {
      sampleRevision.current++;
      setPending(false);
    }
  }

  return (
    <section className="session-controls" aria-labelledby="fingerprint-samples-heading">
      <div className="session-controls-heading"><h2 id="fingerprint-samples-heading">Saved fingerprint samples</h2></div>
      {samples && (samples.length ? (
        <ul className="network-list">
          {samples.map(sample => (
            <li key={sample.id}>
              <span>{sample.family}{sample.osHint ? ` · ${sample.osHint}` : ''}<code>{frameName(sample.evidence.source)} · {sample.evidence.hash}</code></span>
              {confirmation === sample.id ? <div className="session-inline-actions">
                <button type="button" className="text-button" disabled={pending} onClick={() => remove(sample.id)}>Confirm removal</button>
                <button type="button" className="text-button" onClick={() => setConfirmation(null)}>Cancel</button>
              </div> : <button type="button" className="text-button" disabled={pending} onClick={() => setConfirmation(sample.id)}>Remove sample</button>}
            </li>
          ))}
        </ul>
      ) : <p className="micro-note">Save an observation from an enrolled device in Profiler.</p>)}
      {!samples && !loadError && <p className="micro-note" role="status">Loading saved samples…</p>}
      {loadError && <p className="inline-error" role="alert">{loadError}</p>}
      {error && <p className="inline-error" role="alert">{error}</p>}
    </section>
  );
}
