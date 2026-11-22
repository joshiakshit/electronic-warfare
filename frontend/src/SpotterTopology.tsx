import { useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { AccessPointObservation, ClientLink } from './api';
import { observationValue } from './observations';
import { endpointKey, linkEvidence, linkTouches, topologyDiagram, type TopologyEndpoint } from './spotterTopology';

const evidenceLabels = {
  association: 'Association or reassociation',
  data: 'Data frames',
  other: 'Other evidence',
} as const;

function apName(ap: AccessPointObservation) {
  return observationValue('ssid', ap);
}

export function SpotterTopology({ accessPoints, edges, selected, onSelect }: {
  accessPoints: AccessPointObservation[];
  edges: ClientLink[];
  selected: TopologyEndpoint | null;
  onSelect: (endpoint: TopologyEndpoint | null) => void;
}) {
  const graph = useMemo(() => topologyDiagram(accessPoints, edges, selected), [accessPoints, edges, selected]);
  const selectValue = selected ? endpointKey(selected) : '';
  const wireColumn = useRef<HTMLDivElement>(null);
  const [wireWidth, setWireWidth] = useState(0);
  const hasDiagram = graph.aps.length > 0;
  useLayoutEffect(() => {
    const column = wireColumn.current;
    if (!column) return;
    const measure = () => setWireWidth(column.clientWidth);
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(column);
    return () => observer.disconnect();
  }, [hasDiagram]);

  if (!hasDiagram) {
    return <div className="report-empty"><strong>No topology observations yet</strong></div>;
  }

  const height = Math.max(graph.aps.length, graph.clients.length) * 54;
  const apPositions = new Map(graph.aps.map((ap, index) => [ap.bssid, height * (index + 0.5) / graph.aps.length]));
  const clientPositions = new Map(graph.clients.map((id, index) => [id, height * (index + 0.5) / graph.clients.length]));
  const activeLinks = selected ? graph.links.filter(link => linkTouches(selected, link)) : [];
  const neighborAps = new Set(activeLinks.map(link => link.bssid));
  const neighborClients = new Set(activeLinks.map(link => link.clientId));
  const evidence = new Set(graph.links.map(link => linkEvidence(link.source)));

  function toggle(endpoint: TopologyEndpoint) {
    onSelect(endpointKey(endpoint) === selectValue ? null : endpoint);
  }

  return (
    <div className="spotter-topology">
      {graph.bounded && (
        <div className="topology-toolbar">
          <span>
            Showing {graph.aps.length}/{graph.allAps.length} APs, {graph.clients.length}/{graph.allClients.length} clients,
            and {graph.links.length}/{edges.length} observed links
          </span>
          <label>
            <span>Focus endpoint</span>
            <select value={selectValue} onChange={event => {
              const value = event.target.value;
              const separator = value.indexOf(':');
              onSelect(value ? { kind: value.startsWith('ap:') ? 'ap' : 'client', id: value.slice(separator + 1) } : null);
            }}>
              <option value="">All endpoints</option>
              <optgroup label="Access points">
                {graph.allAps.map(ap => (
                  <option key={ap.bssid} value={endpointKey({ kind: 'ap', id: ap.bssid })}>{apName(ap)} · {ap.bssid}</option>
                ))}
              </optgroup>
              <optgroup label="Observed clients">
                {graph.allClients.map(id => <option key={id} value={endpointKey({ kind: 'client', id })}>{id}</option>)}
              </optgroup>
            </select>
          </label>
        </div>
      )}
      <div className="topology-grid">
        <h3>Access points</h3>
        <h3 className="topology-client-heading">Observed clients</h3>
        <div className="topology-nodes">
          {graph.aps.map(ap => {
            const endpoint: TopologyEndpoint = { kind: 'ap', id: ap.bssid };
            const name = apName(ap);
            return (
              <button key={ap.bssid} type="button" className="topology-node"
                      aria-label={`Access point ${name}, ${ap.bssid}`} aria-pressed={endpointKey(endpoint) === selectValue}
                      aria-controls="spotter-client-links" data-neighbor={neighborAps.has(ap.bssid) || undefined}
                      title={`${name} · ${ap.bssid}`} onClick={() => toggle(endpoint)}>
                <span>{name}</span>
                <code>{ap.channel ? `CH ${ap.channel} · ` : ''}{ap.bssid}</code>
              </button>
            );
          })}
        </div>
        <div ref={wireColumn} className="topology-wires" style={{ height }} aria-hidden="true">
          {wireWidth > 0 && graph.links.map(link => {
            const from = apPositions.get(link.bssid)!;
            const to = clientPositions.get(link.clientId)!;
            const dy = to - from;
            const active = selected && linkTouches(selected, link);
            return <span key={JSON.stringify([link.bssid, link.clientId])}
                         className={`topology-wire ${linkEvidence(link.source)}${active ? ' active' : ''}`}
                         style={{ top: from, width: Math.hypot(wireWidth, dy), transform: `rotate(${Math.atan2(dy, wireWidth)}rad)` }} />;
          })}
        </div>
        <div className="topology-nodes">
          {graph.clients.length ? graph.clients.map(id => {
            const endpoint: TopologyEndpoint = { kind: 'client', id };
            return (
              <button key={id} type="button" className="topology-node"
                      aria-label={`Client ${id}`} aria-pressed={endpointKey(endpoint) === selectValue}
                      aria-controls="spotter-client-links" data-neighbor={neighborClients.has(id) || undefined}
                      title={id} onClick={() => toggle(endpoint)}>
                <code>{id}</code>
              </button>
            );
          }) : <span className="topology-empty-clients">No client links observed</span>}
        </div>
      </div>
      {evidence.size > 0 && (
        <ul className="topology-key" aria-label="Wire evidence">
          {Object.entries(evidenceLabels).filter(([kind]) => evidence.has(kind as keyof typeof evidenceLabels)).map(([kind, label]) => (
            <li key={kind}><span className={`topology-swatch ${kind}`} aria-hidden="true" />{label}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
