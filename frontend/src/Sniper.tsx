import { useEffect, useState } from 'react';
import { CircleStop, Play } from 'lucide-react';
import { get, send, type AccessPointObservation, type SniperMove, type SniperReport } from './api';
import { channelReading, sniperStartRequest } from './navigation';
import { date, short } from './observations';
import { startSnapshotPolling } from './snapshotPolling';

const moveLabels: Record<SniperMove['trigger'], string> = {
  CSA: '802.11h CSA',
  SILENCE_SWEEP: 'Silence sweep',
  HEURISTIC_BSSID_ROTATION: 'Heuristic hotspot BSSID rotation',
  AFFILIATED_LINK_SWITCH: 'Affiliated link switch',
  OBSERVED: 'Observed channel change',
};

export function Sniper({ data, onChanged }: { data: SniperReport; onChanged: (report: SniperReport) => void }) {
  const [targetKind, setTargetKind] = useState<'ssid' | 'ap'>('ssid');
  const [ssid, setSsid] = useState('');
  const [apId, setApId] = useState('');
  const [accessPoints, setAccessPoints] = useState<AccessPointObservation[]>();
  const [listError, setListError] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState('');
  const { run, available } = data;
  const runId = run?.id;
  const active = Boolean(runId && run?.state !== 'IDLE');
  const candidates = run?.state === 'SEARCHING' || run?.state === 'SELECTING' ? run.candidates ?? [] : [];
  const sweeping = run?.state === 'SEARCHING' || run?.state === 'LOST_SEARCHING';
  const selectedAp = accessPoints?.some(ap => ap.bssid === apId) ? apId : '';
  const byName = targetKind === 'ssid';
  const request = byName ? sniperStartRequest(ssid, available) : available && selectedAp ? { apId: selectedAp } : null;

  useEffect(() => {
    if (targetKind !== 'ap' || !available) return;
    const poll = startSnapshotPolling(async signal => {
      try {
        const report = await get<{ accessPoints: AccessPointObservation[] }>('/api/capture/access-points', signal);
        if (signal.aborted) return;
        setAccessPoints(report.accessPoints);
        setListError('');
      } catch (failure) {
        if (signal.aborted) return;
        setAccessPoints(undefined);
        setListError(failure instanceof Error ? failure.message : 'Could not load observed access points');
      }
    }, 4000);
    return poll.stop;
  }, [targetKind, available]);

  async function submit(action: () => Promise<SniperReport>) {
    if (pending) return;
    setPending(true);
    setError('');
    try {
      onChanged(await action());
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Sniper request failed');
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="sniper-panel">
      <form className="sniper-form" onSubmit={event => {
        event.preventDefault();
        if (request) void submit(() => send<SniperReport>('/api/sniper', 'POST', request));
      }}>
        <label className="sniper-method">Find by
          <select value={targetKind} onChange={event => setTargetKind(event.target.value === 'ap' ? 'ap' : 'ssid')}>
            <option value="ssid">Network name</option>
            <option value="ap">Observed access point</option>
          </select>
        </label>
        {byName ? (
          <label>Network name (SSID)
            <input value={ssid} maxLength={32} onChange={event => setSsid(event.target.value)} placeholder="Enter exact SSID" />
          </label>
        ) : (
          <label>Access point
            <select value={selectedAp} onChange={event => setApId(event.target.value)}
              disabled={!available || !accessPoints?.length || pending}>
              <option value="">{available && !accessPoints && !listError ? 'Loading…' : 'Choose an observed access point'}</option>
              {accessPoints?.map(ap => (
                <option key={ap.bssid} value={ap.bssid}>
                  {ap.ssid || 'Hidden network'} · {ap.bssid}{ap.channel ? ` · CH ${ap.channel}` : ''}{ap.frequencyMhz ? ` · ${ap.frequencyMhz} MHz` : ''}
                </option>
              ))}
            </select>
          </label>
        )}
        <button type="submit" disabled={pending || !request}><Play size={13} />{byName ? 'Start search' : 'Follow access point'}</button>
        <button type="button" className="secondary" disabled={pending || !active} onClick={() => {
          if (runId) void submit(() => send<SniperReport>(`/api/sniper/${encodeURIComponent(runId)}`, 'DELETE'));
        }}><CircleStop size={13} />Stop Sniper</button>
      </form>
      {!available && <p className="micro-note">Start live passive Wi-Fi capture to make Sniper available.</p>}
      {available && byName && ssid && !request && <p className="micro-note">A network name can contain up to 32 Wi-Fi bytes.</p>}
      {available && !byName && accessPoints?.length === 0 && <p className="micro-note">No access points observed in this capture.</p>}
      {!byName && listError && <p className="inline-error" role="alert">{listError}</p>}
      {error && <p className="inline-error" role="alert">{error}</p>}
      {run && (
        <div className="detail-grid sniper-state">
          <div><span>Search state</span><b>{short(run.state)}</b></div>
          <div><span>Target network</span><b>{short(run.targetSsid || run.lockedSsid)}</b></div>
          <div><span>Selected AP</span><b className="mono">{short(run.lockedApId)}</b></div>
          <div><span>Channel / frequency</span><b>{channelReading(run.lockedChannel, run.lockedFrequencyMhz) || '—'}</b></div>
          <div><span>Started</span><b>{date(run.startedAt)}</b></div>
          <div><span>Last heard</span><b>{date(run.lastHeard?.timestamp)}</b></div>
          {sweeping && run.activeSweepFrequencyMhz != null &&
            <div><span>Active sweep channel</span><b>{channelReading(run.activeSweepChannel, run.activeSweepFrequencyMhz)}</b></div>}
          {run.pendingChannelSwitch && (
            <div><span>Pending 802.11h CSA</span>
              <b>{channelReading(run.pendingChannelSwitch.channel, run.pendingChannelSwitch.frequencyMhz)}</b></div>
          )}
          {run.pendingAffiliatedLinkFrequencyMhz != null &&
            <div><span>Verifying affiliated link</span><b>{channelReading(null, run.pendingAffiliatedLinkFrequencyMhz)}</b></div>}
          {!!run.decoyFramesIgnored && <div><span>Decoy frames ignored</span><b>{run.decoyFramesIgnored}</b></div>}
          {!!run.spoofWarnings && <div><span>Suspected CSA spoofing</span><b>{run.spoofWarnings}</b></div>}
          {run.bssidRotated && <div><span>AP identity</span><b>Heuristic hotspot BSSID rotation</b></div>}
          {run.mldId && <div><span>Multi-link device</span><b className="mono">{run.mldId}</b></div>}
          {run.sweepChannelCount != null && (run.state === 'SEARCHING' || !!run.unavailableSweepChannels) && (
            <div><span>Frequencies sampled</span><b>{run.channelsSwept ?? 0} / {run.sweepChannelCount}
              {!!run.unavailableSweepChannels && ` · ${run.unavailableSweepChannels} unavailable`}</b></div>
          )}
        </div>
      )}
      {candidates.length > 0 && (
        <>
          <div className="candidate-label">Matching access points · select one to follow</div>
          <div className="candidate-list">
            {candidates.map(candidate => (
              <button type="button" key={candidate.apId} disabled={pending || !available}
                onClick={() => submit(() => send<SniperReport>('/api/sniper/select', 'POST', { apId: candidate.apId }))}>
                <span>{candidate.ssid || run?.targetSsid || 'Hidden network'}</span>
                <code>{candidate.apId}</code>
                <span>{channelReading(candidate.channel, candidate.frequencyMhz)}</span>
              </button>
            ))}
          </div>
        </>
      )}
      {!!run?.affiliatedLinks?.length && (
        <section className="sniper-evidence">
          <h2>Affiliated links</h2>
          <div className="table-wrap">
            <table aria-label="Affiliated links">
              <thead><tr><th>Band</th><th>Channel / frequency</th><th>Link ID</th><th>AP</th><th>Action</th></tr></thead>
              <tbody>{run.affiliatedLinks.map(link => (
                <tr key={link.apId}>
                  <td>{link.band}</td>
                  <td>{channelReading(link.channel, link.frequencyMhz)}</td>
                  <td>{link.linkId ?? '—'}</td>
                  <td className="mono">{link.apId}</td>
                  <td>{link.supported ? (
                    <button className="text-button" type="button"
                      disabled={pending || !available || run.state !== 'LOCKED' || run.opsPaused
                        || run.pendingChannelSwitch?.tunedAtMs != null || run.pendingAffiliatedLinkFrequencyMhz != null
                        || run.lockedFrequencyMhz === link.frequencyMhz}
                      onClick={() => void submit(() => send<SniperReport>('/api/sniper/link', 'POST', { frequencyMhz: link.frequencyMhz }))}>
                      Follow link
                    </button>
                  ) : 'Unavailable'}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </section>
      )}
      {!!run?.moves?.length && (
        <section className="sniper-evidence">
          <h2>Channel Move History</h2>
          <div className="table-wrap">
            <table aria-label="Channel Move History">
              <thead><tr><th>From</th><th>To</th><th>Trigger</th><th>Recovery</th><th>Rediscovered</th></tr></thead>
              <tbody>{run.moves.map((move, index) => (
                <tr key={`${move.rediscoveredAtMs}-${index}`}>
                  <td>{channelReading(move.fromChannel, move.fromFrequencyMhz)}</td>
                  <td>{channelReading(move.toChannel, move.toFrequencyMhz)}</td>
                  <td>{moveLabels[move.trigger] ?? moveLabels.SILENCE_SWEEP}</td>
                  <td>{Math.max(0, move.rediscoveredAtMs - move.lostAtMs)} ms</td>
                  <td>{date(move.rediscoveredAtMs)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
