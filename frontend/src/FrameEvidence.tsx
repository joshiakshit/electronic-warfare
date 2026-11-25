import type { ApSecurityDetails, ManagementFeatures, RadioObservation } from './api';
import { date } from './observations';

export function ManagementEvidence({ features, modes, akms, security }: {
  features?: ManagementFeatures | null; modes?: string[]; akms?: string[]; security?: ApSecurityDetails;
}) {
  const supported = [
    features?.radioMeasurement && 'Radio measurement (802.11k)',
    features?.neighborReport && 'Neighbor report (802.11k)',
    features?.bssTransition && 'BSS transition management (802.11v)',
    features?.wnmSleep && 'WNM sleep (802.11v)',
    features?.timBroadcast && 'TIM broadcast (802.11v)',
    features?.fastTransition && 'Fast BSS transition (802.11r)',
    features?.twtResponder && 'TWT responder',
  ].filter(Boolean);
  const wps = security?.wpsInfo;
  return <FrameFields title="Advertised capabilities" fields={[
    ['Security modes', modes?.join(', ')], ['RSN authentication suites', akms?.join(', ')],
    ['Group management cipher', security?.groupManagementCipher], ['RSNXE', security?.rsnxeFeatures?.join(', ')],
    ['Beacon protection', advertised(security?.beaconProtection)], ['OCVC', advertised(security?.ocvc)],
    ['WPS status', wps && [wps.state, wps.apSetupLocked == null ? 'Lock state unknown'
      : wps.apSetupLocked ? 'Locked' : 'Unlocked'].filter(Boolean).join(' · ')],
    ['Management features', supported.join(', ')], ['Mobility domain', features?.mobilityDomain],
    ['Extended Capabilities', features?.extendedCapabilitiesHex],
  ]} />;
}

export function RadioFrameEvidence({ observation, apAdvertisement = false }: {
  observation?: RadioObservation | null; apAdvertisement?: boolean;
}) {
  if (!observation) return null;
  const { metadata, timestamp, frequencyMhz } = observation;
  const ht = metadata.ht;
  const he = metadata.he;
  const htRate = ht && [ht.mcs == null ? null : `MCS ${ht.mcs}`, ht.bandwidth,
    ht.shortGuardInterval == null ? null : ht.shortGuardInterval ? 'Short GI' : 'Long GI'].filter(Boolean).join(' · ');
  const heRate = he && [he.format, he.mcs == null ? null : `MCS ${he.mcs}`, he.bandwidthOrRu,
    unit(he.guardIntervalUs, 'µs GI'), unit(he.spaceTimeStreams, 'space-time streams'), he.dualCarrierModulation && 'DCM',
  ].filter(Boolean).join(' · ');
  const fields: FrameField[] = [
    ['Frequency', frequencyMhz > 0 ? `${frequencyMhz} MHz` : null], ['Signal', unit(metadata.signalDbm, 'dBm')],
    ['Noise', unit(metadata.noiseDbm, 'dBm')], ['SNR', unit(metadata.snrDb, 'dB')],
    ['Antenna', metadata.antenna], ['Legacy data rate', unit(metadata.legacyRateMbps, 'Mbps')],
    ['HT rate parameters', htRate], ['HE rate parameters', heRate],
    ['Channel flags', metadata.channelFlags == null ? null : `0x${metadata.channelFlags.toString(16)}`],
  ];
  if (fields.every(([, value]) => value == null || value === '')) return null;
  const title = apAdvertisement ? 'Captured beacon or probe response reception' : 'Captured frame radio metadata';
  return <FrameFields title={title} fields={[['Observed at', date(timestamp)], ...fields]} />;
}

type FrameField = [string, string | number | null | undefined];

export function FrameFields({ title, fields }: { title: string; fields: FrameField[] }) {
  const observed = fields.filter(([, value]) => value != null && value !== '');
  if (!observed.length) return null;
  return <section className="evidence-group" aria-label={title}>
    <h3>{title}</h3>
    <dl>{observed.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
  </section>;
}

function unit(value: number | null | undefined, suffix: string) {
  return value == null ? null : `${value} ${suffix}`;
}

function advertised(value: boolean | undefined) {
  return value == null ? null : value ? 'Advertised' : 'Unobserved';
}
