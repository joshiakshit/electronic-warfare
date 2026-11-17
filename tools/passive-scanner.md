# Synthetic passive scanner benchmark results

These results come from the seeded simulation in `ScannerEvaluation.java`.
They contain no live captures, network names, device addresses, or credentials.

The dashboard fixture and the passive monitor now use the same discovery policy. For a router on a known channel, the comparison is simply how many of that router's frames survive when the receiver stays there. For discovery, compare with round-robin and count both distinct bursts and frames.

## What caused the original miss?

The receiver started on channel 6, heard silence for 100 ms, then left. The first transmission on 6 came at 1,000 ms. The seeded score selector never returned to 6 during the entire 12-second demo. Visiting 13 channels at least once says very little about when the receiver visited them.

In PhaseModel, a channel without valid samples gets a score of 1. One full quiet sample lowered channel 6's score. The demo made another choice every 100 ms, picked randomly among tied high scores, and excluded silence from a window shortened by tuning. A newly visited quiet channel could therefore still look unseen. There was no switching penalty or revisit deadline in AdaptiveScanner.choose(). The 104 changes consumed 2.6 seconds.

The old live monitor additionally reserved a visit about once a second and listened for at least 250 ms after a successful survey tune. It could also count a quiet partial window as a full observation if the tune had finished by the boundary. The original demo had neither behavior. Both historical policies appear below, with the same transmissions and initial conditions.

## Changes

Each new passive discovery session sweeps channels 1–13 in order. After each confirmed tune, it listens for at least 100 ms, or twice the measured command time up to a 500 ms minimum dwell. A decoded frame on the confirmed channel keeps the receiver there until 200 ms after the most recent frame, subject to a 1.2-second busy-visit cap. The timer applies those conditions at the next decision, so actual visits can be longer. Even sustained traffic eventually yields to the next channel. A failed tune advances the sweep without crediting a visit.

The ordered sweep avoids score ties and gives every channel a turn. The phase model continues to supply Spectrum estimates. A quiet observation now requires a complete confirmed listening window. A heard frame still counts in a partial window. The passive path uses the existing serialized retune worker, session lock, frame timestamp checks, and session teardown. The benchmark sends only received frames and completed tune timings into the discovery policy.

## Original 12-second fixture

All methods start with channel 6 already confirmed. A dash means the receiver heard no frames from that burst. Delay is time from the first transmitted frame to the first captured frame, in ms.

| Method | Frames caught / missed | Bursts found / missed | Delays on 6 / 11 / 1 (ms) | Changes | Switching (ms) |
|---|---:|---:|---|---:|---:|
| Original adaptive demo | 15 / 125 | 2 / 1 | — / 1350 / 950 | 104 | 2600 |
| Previous live rules, simulated | 69 / 71 | 3 / 0 | 550 / 450 / 1150 | 64 | 1600 |
| New adaptive | 59 / 81 | 3 / 0 | 1550 / 50 / 850 | 46 | 1150 |
| Same minimum dwell, no extension | 9 / 131 | 3 / 0 | 1550 / 2150 / 1850 | 60 | 1500 |
| Fixed 6 | 40 / 100 | 1 / 2 | 0 / — / — | 0 | 0 |
| Round-robin | 6 / 134 | 3 / 0 | 350 / 450 / 1150 | 119 | 2975 |

With an unconfirmed initial channel and the first decision at 100 ms, new adaptive starts its sweep at 1. It catches 43 frames with delays of 150, 1850 and 2250 ms. Previous live rules catch 48 frames. This cold-start sensitivity check is included in the detailed results. It assumes no usable reception before the initial tune.

## Choosing a dwell limit

All trials last 12 seconds, with a 100 ms decision clock and one decodable frame every 50 ms during each scripted burst. The original fixture was available during development. The tuning totals below exclude it. Each candidate saw the same four workload families, timing seeds 1 and 2, and retune delays of 10 and 50 ms.

| Busy dwell cap | Frames captured | Bursts found | Switching (ms) |
|---|---:|---:|---:|
| 500 ms | 667 | 30 | 25130 |
| 1200 ms | 1032 | 30 | 21890 |
| 2400 ms | 1249 | 26 | 19800 |

We chose 1200 ms to keep the highest observed discovery count while collecting more frames. This experiment compares three caps on one policy. It does not establish an optimal cap for other traffic.

## Held-out timings and tune costs

Each row sums nine runs on a workload, crossing three previously unused seeds (73, 149, 311) with 0, 25 and 150 ms retunes. Policies see identical traffic in each paired trial. Continuous traffic is on 6. Short traffic has 12 bursts on randomly chosen channels, each lasting 250–649 ms. Several busy channels has five overlapping long bursts on distinct channels. Mostly quiet has two 150 ms bursts in 12 seconds. Each starts at a seeded offset. Different workloads contain different numbers of transmitted frames.

| Workload | Method | Frames caught / missed | Bursts found / missed | Changes | Switching (ms) |
|---|---|---:|---:|---:|---:|
| Continuous | Previous live rules | 1192 / 968 | 9 / 0 | 279 | 15450 |
| Continuous | New adaptive | 789 / 1371 | 9 / 0 | 369 | 11925 |
| Continuous | Minimum dwell only | 133 / 2027 | 9 / 0 | 609 | 15300 |
| Continuous | Fixed 6 | 2160 / 0 | 9 / 0 | 0 | 0 |
| Continuous | Round-robin | 120 / 2040 | 9 / 0 | 894 | 35775 |
| Short | Previous live rules | 102 / 906 | 25 / 83 | 659 | 27850 |
| Short | New adaptive | 133 / 875 | 20 / 88 | 554 | 14600 |
| Short | Minimum dwell only | 64 / 944 | 28 / 80 | 609 | 15300 |
| Short | Fixed 6 | 27 / 981 | 3 / 105 | 0 | 0 |
| Short | Round-robin | 54 / 954 | 35 / 73 | 894 | 35775 |
| Several | Previous live rules | 1132 / 7085 | 40 / 5 | 476 | 21575 |
| Several | New adaptive | 1380 / 6837 | 45 / 0 | 215 | 9075 |
| Several | Minimum dwell only | 535 / 7682 | 45 / 0 | 609 | 15300 |
| Several | Fixed 6 | 1173 / 7044 | 6 / 39 | 0 | 0 |
| Several | Round-robin | 431 / 7786 | 45 / 0 | 894 | 35775 |
| Quiet | Previous live rules | 4 / 50 | 2 / 16 | 720 | 28800 |
| Quiet | New adaptive | 3 / 51 | 1 / 17 | 608 | 15275 |
| Quiet | Minimum dwell only | 3 / 51 | 1 / 17 | 609 | 15300 |
| Quiet | Fixed 6 | 0 / 54 | 0 / 18 | 0 | 0 |
| Quiet | Round-robin | 0 / 54 | 0 / 18 | 894 | 35775 |

Across these 36 trials, new adaptive collected 2,305 frames and found 75 bursts. Previous live rules collected 2,430 and found 76 while spending 93.675 seconds switching, compared with 50.875 seconds for new adaptive. Several busy channels benefited most from the bounded sweep. A continuously busy router benefited from staying tuned, and round-robin found more short bursts. Even the best method on the quiet workload caught only two of 18 bursts.

## Repeat offline

From the repository root with Maven and a full JDK 21 or newer:

```sh
mvn test
mkdir -p target/scanner-evaluation
javac -cp target/classes -d target/scanner-evaluation tools/ScannerEvaluation.java
java -cp target/classes:target/scanner-evaluation ewave.core.ScannerEvaluation tune
java -cp target/classes:target/scanner-evaluation ewave.core.ScannerEvaluation > target/scanner-results.tsv
diff -u tools/passive-scanner-results.tsv target/scanner-results.tsv
```

The [trial results](passive-scanner-results.tsv) include every method's frame and burst totals, change count, elapsed switching time and each burst's individual delay, in fixture order. A dash is a miss and zero is immediate detection. Switching time is clipped at trial end. Cold-start runs count the initial tune command and exclude the 100 ms waiting for the first decision.

## Limits and presentation

One adapter hears one channel at a time. The offline receiver has perfect decoding on its tuned channel, no buffering or driver jitter and successful tune commands with a constant cost within each trial. Frames have equal value here. Real packets differ in what they reveal, and overlapping channels, noise, load, kernel drops and irregular traffic will affect reception. Live capture cannot count unseen transmissions without an independent reference. Test successes and simulation totals measure software behavior.

**For the lab presentation:** “The old demo left channel 6 before its burst and kept hopping among channels it knew little about. Our receiver now checks each channel in turn and listens longer when it hears frames. In the example it heard all three bursts and spent 1.15 seconds changing channels. A fast sweep still found more short bursts in separate trials. For one known router, staying on its channel collected the most frames.”

## Follow-up experiment: returning to sustained traffic

The current sweep forgets which channel was busy as soon as it leaves. An initial prototype returned after three more sweep visits whenever it had heard at least 800 ms of sustained activity. In 18 several-busy-channel trials it captured 2,775 frames versus 2,634, but found 84 bursts versus 88. That cost motivated a narrower rule.

The offline candidate first completes a 13-channel sweep. A channel qualifies for an early return if it was the only channel with sustained activity in the previous sweep, it still has sustained activity when the receiver leaves it, and no competitor has qualified in the current sweep. Here sustained means observed frames span at least 800 ms in a single visit and the last frame arrived under 200 ms before departure. After three regular visits the receiver may check that channel again, provided its information is under two seconds old. It then resumes at the next channel in the sweep. It uses the existing dwell rules.

Six fresh timing seeds crossed with 10, 40 and 120 ms delays give 18 paired trials per workload. The moving-router case starts on a randomly chosen channel and moves to a different one 6–9 seconds into the trial. These trials still assume perfect decoding, periodic frame spacing, and an initial receiver channel of 6. They do not measure general radio performance.

| Workload | Frames, current → candidate | Bursts found, current → candidate | Switching seconds, current → candidate |
|---|---:|---:|---:|
| Continuous channel 6 | 1,436 → 2,240 | 18 → 18 | 29.70 → 23.82 |
| Moving router | 1,345 → 1,634 | 34 → 35 | 30.18 → 28.28 |
| Short bursts | 259 → 259 | 43 → 43 | 37.07 → 37.07 |
| Several busy channels | 2,437 → 2,437 | 84 → 84 | 21.33 → 21.33 |
| Mostly quiet | 12 → 12 | 4 → 4 | 39.45 → 39.45 |

Run the prototype with JDK 21 or newer after compiling the project. Its output includes every burst delay and miss. The live default still uses the ordered sweep.

```sh
mkdir -p target/scanner-evaluation
javac -cp target/classes -d target/scanner-evaluation tools/ScannerEvaluation.java tools/RevisitTrial.java
java -cp target/scanner-evaluation:target/classes ewave.core.RevisitTrial
```
