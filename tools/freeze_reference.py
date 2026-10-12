"""Explicitly regenerate frozen migration fixtures; never run during Java tests."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import numpy as np
from ewscan.agents.phase import PhaseOccupancy
from ewscan.agents.period import _phase_likelihood

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'src/test/resources/reference'

def freeze(name, bands, capacity, observations, max_period=200):
    model = PhaseOccupancy(bands, capacity, max_period=max_period)
    lines = [f'C,{bands},{capacity},{max_period}']
    checkpoints = 0
    def snapshot(tick):
        nonlocal checkpoints
        checkpoints += 1
        scores = model.upper_bound(tick)
        lines.append('G,' + str(tick) + ',' + str(model.coupled_period() or 0) + ',' + ':'.join(map(str, model.coupled_members())))
        for b in range(bands):
            mean, spread = model.posterior(b, tick)
            slots, dets = model._history.recent(b)
            likelihood = _phase_likelihood(slots, dets, model.period(b) or 1)
            lines.append(f'Q,{tick},{b},{model.period(b) or 0},{mean:.17g},{spread:.17g},{scores[b]:.17g},{likelihood:.17g}')
        # Compare selections only when scores are outside the reference tie tolerance.
        order = np.argsort(scores)[::-1]
        if bands == 1 or not np.isclose(scores[order[0]], scores[order[1]], rtol=1e-12, atol=1e-12):
            lines.append(f'D,{tick},{order[0]}')
    snapshot(0)
    for i, (band, tick, detection) in enumerate(observations):
        model.observe(band, tick, detection)
        lines.append(f'O,{tick},{band},{int(detection)}')
        if i < 10 or (i + 1) % 48 == 0:
            snapshot(tick + 1)
    final = observations[-1][1] + 1
    for tick in range(final, final + 280):
        snapshot(tick)
    path = OUT / (name + '.csv')
    path.write_text('\n'.join(lines) + '\n')
    return {'file': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'observations': len(observations), 'checkpoints': checkpoints, 'final_periods': model._period, 'coupled_period': model.coupled_period(), 'coupled_members': model.coupled_members()}

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    cases = []
    rng = np.random.default_rng(0)
    cases.append(freeze('sparse_periodic', 2, 2000, [(0,t,t%20 in {5,6,7}) for t in range(2000) if rng.random()<.12]))
    rng = np.random.default_rng(3)
    cases.append(freeze('aperiodic', 1, 128, [(0,t,bool(rng.random()<.3)) for t in range(1800) if rng.random()<.15]))
    cases.append(freeze('cw_quiet', 3, 128, [(b,t,b==0 and t%30!=7) for t in range(400) for b in range(2)]))
    rng = np.random.default_rng(0); state = True; obs=[]
    for t in range(650):
        state = rng.random()>.05 if state else rng.random()<.05
        obs.append((0,t,bool(state)))
    cases.append(freeze('bursty', 1, 128, obs))
    rng = np.random.default_rng(0); active=set(rng.choice(255,64,replace=False).tolist())
    cases.append(freeze('long_period', 1, 4000, [(0,t,t%255 in active) for t in range(4000) if rng.random()<.5],300))
    rng=np.random.default_rng(12); holders=rng.integers(0,4,255); obs=[]
    for t in range(3000):
        b=int(rng.choice(5,p=[.75,.06,.06,.06,.07])); hit=holders[t%255]==b if b<4 else rng.random()<.25
        obs.append((b,t,bool(hit)))
    cases.append(freeze('coupled',5,3000,obs))
    sources = ['ewscan/agents/'+n+'.py' for n in ['phase','period','history','pomdp','base']]
    manifest={'revision': subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(), 'python':sys.version, 'numpy':np.__version__, 'sources':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sources}, 'tolerance':1e-9,'cases':cases}
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
if __name__=='__main__': main()
