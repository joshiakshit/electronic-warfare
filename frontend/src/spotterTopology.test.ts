import { describe, expect, it } from 'vitest';
import type { ClientLink } from './api';
import { linkEvidence, linkTouches, topologyDiagram, type TopologyEndpoint } from './spotterTopology';

function observation(bssid: string, clientId: string, lastSeen = 1, source = 'ASSOC'): ClientLink {
  return { bssid, clientId, lastSeen, source, firstSeen: 1, evidenceCount: 4 };
}

describe('Spotter topology', () => {
  it('includes both ends of each observed link and leaves isolated access points unconnected', () => {
    const links = [observation('ap-a', 'client-x'), observation('ap-b', 'client-x', 2, 'DATA')];
    const graph = topologyDiagram([{ bssid: 'ap-a', ssid: 'Lab' }, { bssid: 'ap-c', stationCount: 25 }], links, null);

    expect(graph.bounded).toBe(false);
    expect(graph.aps.map(ap => ap.bssid)).toEqual(['ap-a', 'ap-b', 'ap-c']);
    expect(graph.clients).toEqual(['client-x']);
    expect(graph.links).toEqual(links);
    expect(graph.links.map(link => linkEvidence(link.source))).toEqual(['association', 'data']);
  });

  it('prioritizes the selected endpoint outside the default diagram and retains its complete report', () => {
    const links = Array.from({ length: 25 }, (_, index) =>
      observation(`ap-${index % 9}`, `client-${index}`, index + 1));
    const apSelection: TopologyEndpoint = { kind: 'ap', id: 'ap-0' };
    const clientSelection: TopologyEndpoint = { kind: 'client', id: 'client-0' };
    const apGraph = topologyDiagram([], links, apSelection);
    const clientGraph = topologyDiagram([], links, clientSelection);

    expect(apGraph.bounded).toBe(true);
    expect(apGraph.aps).toHaveLength(6);
    expect(apGraph.clients).toHaveLength(8);
    expect(apGraph.allClients).toHaveLength(25);
    expect(apGraph.links.filter(link => linkTouches(apSelection, link))).toEqual([links[18], links[9], links[0]]);
    expect(clientGraph.links).toContain(links[0]);
    expect(clientGraph.clients).toContain('client-0');
  });

  it('bounds a dense diagram while keeping every visible wire attached to visible nodes', () => {
    const links = Array.from({ length: 48 }, (_, index) => observation(
      `ap-${index % 6}`, `client-${Math.floor(index / 6)}`, index + 1,
    ));
    const selected: TopologyEndpoint = { kind: 'ap', id: 'ap-0' };
    const graph = topologyDiagram([], links, selected);

    expect(graph.links).toHaveLength(24);
    expect(graph.links.filter(link => linkTouches(selected, link))).toHaveLength(8);
    expect(graph.links.every(link => graph.aps.some(ap => ap.bssid === link.bssid)
      && graph.clients.includes(link.clientId) && links.includes(link))).toBe(true);
  });

  it('distinguishes AP and client IDs and treats unknown link sources separately', () => {
    const link = observation('shared-id', 'other-id');
    expect(linkTouches({ kind: 'ap', id: 'shared-id' }, link)).toBe(true);
    expect(linkTouches({ kind: 'client', id: 'shared-id' }, link)).toBe(false);
    expect(linkEvidence('REASSOC')).toBe('association');
    expect(linkEvidence('future-evidence')).toBe('other');
  });
});
