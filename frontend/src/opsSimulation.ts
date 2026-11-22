export function simulatedOperation(operation: string, target: string) {
  const cleanTarget = target.trim();
  if (!cleanTarget) return null;
  return { state: 'running' as const, output: `SIMULATED · ${operation} started for ${cleanTarget}. No backend operation request was sent.` };
}
export function simulatedStop(operation: string) {
  return { state: 'stopped' as const, output: `SIMULATED · ${operation} stopped. No backend operation request was sent.` };
}
