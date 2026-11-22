import { useEffect, useRef, useState } from 'react';
import { get, importRecording, send, type Recording, type WifiStatus } from './api';
import { date } from './observations';

const maxRecordingMiB = 128;
const maxRecordingBytes = maxRecordingMiB * 1024 * 1024;

export type RunCaptureAction = (request: () => Promise<WifiStatus>, success: string) => Promise<void>;

export interface CaptureActions {
  pending: boolean;
  error: string;
  message: string;
  run: RunCaptureAction;
}

export function CaptureFeedback({ actions }: { actions: CaptureActions }) {
  return (
    <>
      {actions.pending && <p className="micro-note" role="status">Updating session…</p>}
      {actions.message && <p className="micro-note" role="status">{actions.message}</p>}
      {actions.error && <p className="inline-error" role="alert">{actions.error}</p>}
    </>
  );
}

export function CaptureControls({ wifi, connected, actions, onRecordings }: {
  wifi?: WifiStatus; connected: boolean; actions: CaptureActions; onRecordings: () => void;
}) {
  const [adapters, setAdapters] = useState<string[]>([]);
  const [adapterError, setAdapterError] = useState('');
  const [loadingAdapters, setLoadingAdapters] = useState(false);
  const [discovery, setDiscovery] = useState(0);
  const [requestedAdapter, setRequestedAdapter] = useState('');
  const [mode, setMode] = useState('watch');
  const [frequency, setFrequency] = useState('');
  const running = !!wifi?.captureRunning;
  const adapter = adapters.includes(requestedAdapter) ? requestedAdapter
    : wifi?.captureInterface && adapters.includes(wifi.captureInterface) ? wifi.captureInterface : adapters[0] ?? '';

  useEffect(() => {
    if (!connected || running) return;
    const controller = new AbortController();
    setLoadingAdapters(true);
    setAdapterError('');
    get<string[]>('/api/capture/adapters', controller.signal).then(setAdapters).catch((error: Error) => {
      if (controller.signal.aborted) return;
      setAdapters([]);
      setAdapterError(error.message);
    }).finally(() => {
      if (!controller.signal.aborted) setLoadingAdapters(false);
    });
    return () => controller.abort();
  }, [connected, running, discovery]);

  const tuneFrequency = Number(frequency);
  const canTune = Number.isInteger(tuneFrequency) && tuneFrequency >= 2300 && tuneFrequency <= 7125;
  return (
    <section className="session-controls" aria-labelledby="capture-controls-heading">
      <div className="session-controls-heading">
        <h2 id="capture-controls-heading">Capture controls</h2>
        <button type="button" className="text-button" onClick={onRecordings}>Saved recordings</button>
      </div>
      {!connected ? <p className="micro-note">Waiting for the local API.</p> : running ? (
        <div className="session-active-controls">
          {wifi?.captureMode === 'watch' && (
            <form className="capture-control-form" onSubmit={event => {
              event.preventDefault();
              if (canTune) actions.run(
                () => send<WifiStatus>('/api/capture/channel', 'POST', { frequencyMhz: tuneFrequency }),
                `Monitor tuned to ${tuneFrequency} MHz.`,
              );
            }}>
              <label>Frequency (MHz)<input type="number" min="2300" max="7125" step="1"
                value={frequency} onChange={event => setFrequency(event.target.value)} placeholder="2437" required /></label>
              <button type="submit" disabled={actions.pending || !canTune}>Tune monitor</button>
            </form>
          )}
          <button type="button" className="session-secondary" disabled={actions.pending} onClick={() => actions.run(
            () => send<WifiStatus>('/api/capture/stop', 'POST', {}),
            'Capture stopped. Observations are still available.',
          )}>{wifi?.captureMode === 'replay' ? 'Stop replay' : 'Stop capture'}</button>
        </div>
      ) : (
        <>
          <form className="capture-control-form" onSubmit={event => {
            event.preventDefault();
            if (adapter) actions.run(
              () => send<WifiStatus>('/api/capture/start', 'POST', { mode, interface: adapter, requireIdle: true }),
              'Capture start requested. See capture health for receiver status.',
            );
          }}>
            <label>Monitor interface
              <select value={adapter} onChange={event => setRequestedAdapter(event.target.value)} disabled={!adapters.length || loadingAdapters}>
                {!adapters.length && <option value="">{loadingAdapters ? 'Looking for adapters…' : 'No prepared monitor interface'}</option>}
                {adapters.map(name => <option value={name} key={name}>{name}</option>)}
              </select>
            </label>
            <label>Capture mode
              <select value={mode} onChange={event => setMode(event.target.value)}>
                <option value="watch">Fixed-channel watch</option>
                <option value="scan">Adaptive scan</option>
              </select>
            </label>
            <button type="submit" disabled={!adapter || loadingAdapters || actions.pending}>Start passive capture</button>
            <button type="button" className="session-secondary" disabled={loadingAdapters || actions.pending}
              onClick={() => setDiscovery(value => value + 1)}>Refresh adapters</button>
          </form>
          {adapterError && <p className="inline-error" role="alert">{adapterError}</p>}
          {!adapter && !loadingAdapters && !adapterError && <p className="micro-note">Prepare a monitor interface with the launcher to use live capture.</p>}
        </>
      )}
      <CaptureFeedback actions={actions} />
    </section>
  );
}

export function SavedRecordings({ entries, wifi, connected, actions, onImported }: {
  entries?: Recording[]; wifi?: WifiStatus; connected: boolean;
  actions: CaptureActions; onImported: (recording: Recording) => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState('');
  const [uploadStatus, setUploadStatus] = useState('');
  const picker = useRef<HTMLInputElement>(null);

  function selectFile(candidate: File | null) {
    setUploadStatus('');
    if (candidate && candidate.size > maxRecordingBytes) {
      setFile(null);
      setUploadError(`Recording exceeds ${maxRecordingMiB} MiB`);
      return;
    }
    setUploadError('');
    setFile(candidate);
  }

  async function upload() {
    if (!file || uploading || !connected) return;
    setUploading(true);
    setUploadError('');
    setUploadStatus('');
    try {
      const entry = await importRecording(file);
      onImported(entry);
      setFile(null);
      if (picker.current) picker.current.value = '';
      setUploadStatus(`Imported ${entry.name}.`);
    } catch (failure) {
      setUploadError(failure instanceof Error ? failure.message : 'Recording import failed');
    } finally {
      setUploading(false);
    }
  }

  return (
    <section className="session-controls" aria-labelledby="recordings-heading">
      <div className="session-controls-heading"><h2 id="recordings-heading">Recording library</h2></div>
      <form className="capture-control-form" onSubmit={event => { event.preventDefault(); void upload(); }}>
        <label>802.11 PCAP<input ref={picker} type="file" accept=".pcap,application/vnd.tcpdump.pcap"
          disabled={!connected || uploading} onChange={event => selectFile(event.target.files?.[0] ?? null)} /></label>
        <button type="submit" disabled={!file || !connected || uploading}>{uploading ? 'Importing…' : 'Import recording'}</button>
      </form>
      <p className="micro-note">Classic PCAP · Up to {maxRecordingMiB} MiB · Stored on this machine</p>
      {uploadStatus && <p className="micro-note" role="status">{uploadStatus}</p>}
      {uploadError && <p className="inline-error" role="alert">{uploadError}</p>}
      {wifi?.captureRunning && <p className="micro-note">Stop the current capture in Capture health before starting another replay.</p>}
      <CaptureFeedback actions={actions} />
      {entries && (entries.length ? (
        <div className="table-wrap recording-table">
          <table aria-label="Saved recordings">
            <thead><tr><th scope="col">Recording</th><th scope="col">Imported</th><th scope="col">Size</th><th scope="col">Replay</th></tr></thead>
            <tbody>{entries.map(entry => (
              <tr key={entry.id}>
                <td title={entry.name}>{entry.name}{wifi?.recordingId === entry.id && <span className="recording-current">Current session</span>}</td>
                <td>{date(entry.importedAt)}</td><td>{entry.bytes.toLocaleString()} B</td>
                <td><button type="button" className="text-button" aria-label={`Replay ${entry.name}`}
                  disabled={!connected || !!wifi?.captureRunning || actions.pending}
                  onClick={() => actions.run(
                    () => send<WifiStatus>(`/api/recordings/${encodeURIComponent(entry.id)}/replay`, 'POST', {}),
                    `Replay started for ${entry.name}. See Capture health for its current state.`,
                  )}>Replay</button></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      ) : <div className="report-empty"><strong>No saved recordings</strong></div>)}
    </section>
  );
}
