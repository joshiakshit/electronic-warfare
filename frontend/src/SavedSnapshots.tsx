import { useEffect, useState } from 'react';
import { get, send, type SavedSnapshot, type SnapshotEntry } from './api';
import { date } from './observations';

export function SavedSnapshots({ connected, sessionId, onOpen }: {
  connected: boolean; sessionId?: string; onOpen: (snapshot: SavedSnapshot) => void;
}) {
  const [entries, setEntries] = useState<SnapshotEntry[]>();
  const [name, setName] = useState('');
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    if (!connected) return;
    const controller = new AbortController();
    get<SnapshotEntry[]>('/api/sessions', controller.signal).then(
      value => {
        if (controller.signal.aborted) return;
        setEntries(value);
        setError('');
      },
      failure => { if (!controller.signal.aborted) setError(failure.message); },
    );
    return () => controller.abort();
  }, [connected]);

  async function act(action: () => Promise<void>) {
    setPending(true);
    setMessage('');
    setError('');
    try {
      await action();
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Snapshot request failed');
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="session-controls" aria-labelledby="snapshots-heading">
      <div className="session-controls-heading"><h2 id="snapshots-heading">Session snapshots</h2></div>
      <form className="capture-control-form" onSubmit={event => {
        event.preventDefault();
        void act(async () => {
          const entry = await send<SnapshotEntry>('/api/sessions', 'POST', { name, sessionId });
          setEntries(previous => [entry, ...(previous ?? [])]);
          setName('');
          setMessage(`Saved ${entry.name}.`);
        });
      }}>
        <label>Snapshot name<input value={name} maxLength={120} required
          onChange={event => setName(event.target.value)} disabled={!connected || !sessionId || pending} /></label>
        <button type="submit" disabled={!connected || !entries || !sessionId || !name.trim() || pending}>Save snapshot</button>
      </form>
      <p className="micro-note">Save the current passive reports for later review.</p>
      {message && <p className="micro-note" role="status">{message}</p>}
      {error && <p className="inline-error" role="alert">{error}</p>}
      {entries && (entries.length ? (
        <div className="table-wrap recording-table">
          <table aria-label="Saved snapshots">
            <thead><tr><th scope="col">Snapshot</th><th scope="col">Saved</th><th scope="col">Actions</th></tr></thead>
            <tbody>{entries.map(entry => {
              const path = `/api/sessions/${encodeURIComponent(entry.id)}`;
              return (
                <tr key={entry.id}>
                  <td>{entry.name}</td>
                  <td>{date(entry.savedAt)}</td>
                  <td className="snapshot-actions">
                    <button type="button" className="text-button" disabled={!connected || pending}
                      aria-label={`Open ${entry.name}`}
                      onClick={() => void act(async () => onOpen(await get<SavedSnapshot>(path)))}>Open</button>
                    {connected && <a className="text-button" href={`${path}?download=true`}
                      aria-label={`Export ${entry.name}`}>Export JSON</a>}
                    <button type="button" className="text-button" disabled={!connected || pending}
                      aria-label={`Delete ${entry.name}`} onClick={() => {
                        if (!window.confirm(`Delete “${entry.name}”?`)) return;
                        void act(async () => {
                          await send(path, 'DELETE');
                          setEntries(previous => previous?.filter(saved => saved.id !== entry.id));
                          setMessage(`Deleted ${entry.name}.`);
                        });
                      }}>Delete</button>
                  </td>
                </tr>
              );
            })}</tbody>
          </table>
        </div>
      ) : <div className="report-empty"><strong>No saved snapshots</strong></div>)}
    </section>
  );
}
