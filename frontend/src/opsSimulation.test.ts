import { describe, expect, it } from 'vitest';
import { simulatedOperation, simulatedStop } from './opsSimulation';

describe('operation safety simulation', () => {
  it('requires a target and generates only a local simulated response', () => {
    expect(simulatedOperation('Handshake capture', '  ')).toBeNull();
    expect(simulatedOperation('Handshake capture', 'lab-client')).toEqual({
      state: 'running', output: 'SIMULATED · Handshake capture started for lab-client. No backend operation request was sent.',
    });
  });
  it('stops the local simulation without issuing a backend command', () => {
    expect(simulatedStop('PMKID capture').output).toContain('No backend operation request was sent.');
  });
});
