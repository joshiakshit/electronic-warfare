import type { AccessPointObservation, ClientLink } from './api';
import { isActiveLink } from './observations';

export type TopologyEndpoint = { kind: 'ap' | 'client'; id: string };

const maxAccessPoints = 6;
const maxClients = 8;
const maxLinks = 24;

export function linkTouches(endpoint: TopologyEndpoint, link: ClientLink): boolean {
  return endpoint.id === (endpoint.kind === 'ap' ? link.bssid : link.clientId);
}

export function endpointKey(endpoint: TopologyEndpoint): string {
  return `${endpoint.kind}:${endpoint.id}`;
}

export function linkEvidence(source: string): 'association' | 'data' | 'other' {
  if (source === 'ASSOC' || source === 'REASSOC') return 'association';
  return source === 'DATA' ? 'data' : 'other';
}

export function topologyDiagram(accessPoints: readonly AccessPointObservation[], links: readonly ClientLink[],
                                selected: TopologyEndpoint | null) {
  const knownAps = new Map(accessPoints.map(ap => [ap.bssid, ap]));
  const apIds = new Set(knownAps.keys());
  const clientIds = new Set<string>();
  for (const link of links) {
    apIds.add(link.bssid);
    clientIds.add(link.clientId);
  }
  const allAps = Array.from(apIds).sort().map(id => knownAps.get(id) ?? { bssid: id });
  const allClients = Array.from(clientIds).sort();
  const bounded = allAps.length > maxAccessPoints || allClients.length > maxClients || links.length > maxLinks;
  if (!bounded) return { aps: allAps, clients: allClients, links, allAps, allClients, bounded };

  const shownAps = new Set<string>();
  const shownClients = new Set<string>();
  const shownLinks: ClientLink[] = [];
  if (selected?.kind === 'ap' && apIds.has(selected.id)) shownAps.add(selected.id);
  if (selected?.kind === 'client' && clientIds.has(selected.id)) shownClients.add(selected.id);
  const ordered = [...links].sort((a, b) => {
    const priority = selected ? Number(linkTouches(selected, b)) - Number(linkTouches(selected, a)) : 0;
    return priority || Number(isActiveLink(b)) - Number(isActiveLink(a))
      || b.lastSeen - a.lastSeen || a.bssid.localeCompare(b.bssid) || a.clientId.localeCompare(b.clientId);
  });
  for (const link of ordered) {
    if (shownLinks.length === maxLinks) break;
    if (!shownAps.has(link.bssid) && shownAps.size === maxAccessPoints) continue;
    if (!shownClients.has(link.clientId) && shownClients.size === maxClients) continue;
    shownAps.add(link.bssid);
    shownClients.add(link.clientId);
    shownLinks.push(link);
  }
  for (const ap of allAps) {
    if (shownAps.size === maxAccessPoints) break;
    shownAps.add(ap.bssid);
  }
  return {
    aps: allAps.filter(ap => shownAps.has(ap.bssid)),
    clients: allClients.filter(id => shownClients.has(id)),
    links: shownLinks,
    allAps,
    allClients,
    bounded,
  };
}
