package ewave.core;

import ewave.capture.PassiveChannelSurvey;
import ewave.core.ScannerDemo.Receiver;
import java.util.List;

/** Offline experiment. Invoke with the same classpath as ScannerEvaluation. */
public final class RevisitTrial {
    static Receiver revisit() {
        var dwell = ScannerDemo.adaptive(new PassiveChannelSurvey());
        return new Receiver() {
            int cursor = 1, busy, remaining, firstHit = -1, lastHit, expires;
            boolean detour;
            int visits, busyMask, previousMask;
            public void arrived(int now, int channel, int cost) {
                dwell.arrived(now, channel, cost);
                if (!detour) cursor = channel % 13 + 1;
                firstHit = -1;
            }
            public void frame(int now, int channel) {
                dwell.frame(now, channel);
                if (firstHit < 0) firstHit = now;
                lastHit = now;
            }
            public int choose(int now, int current) {
                if (current == 0) return cursor;
                if (dwell.choose(now, current) == current) return current;
                boolean sustained = firstHit >= 0 && lastHit - firstHit >= 800 && now - lastHit < 200;
                int bit = 1 << current;
                if (sustained) busyMask |= bit;
                // A detour never advances the sweep or counts toward its 13 visits.
                if (!detour && ++visits == 13) {
                    previousMask = busyMask;
                    busyMask = 0;
                    visits = 0;
                }
                if (sustained && previousMask == bit && (busyMask & ~bit) == 0) {
                    busy = current;
                    expires = now + 2000;
                    remaining = 3;
                } else if (!detour && busy != 0 && --remaining == 0) {
                    int candidate = busy;
                    busy = 0;
                    if ((busyMask & ~(1 << candidate)) == 0 && now < expires && candidate != current && candidate != cursor) {
                        detour = true;
                        return candidate;
                    }
                }
                detour = false;
                return cursor;
            }
        };
    }

    public static void main(String[] args) {
        System.out.println(ScannerEvaluation.REPORT_HEADER);
        for (String name : List.of("continuous", "short", "several", "quiet", "moving-router")) {
            for (int seed : new int[]{1013, 1117, 1213, 1319, 1423, 1523}) {
                var bursts = name.equals("moving-router")
                        ? movingRouter(seed) : ScannerEvaluation.workload(name, seed);
                for (int cost : new int[]{10, 40, 120}) {
                    ScannerEvaluation.report("trial", name, seed, cost, bursts, "adaptive",
                            ScannerDemo.adaptive(new PassiveChannelSurvey()));
                    ScannerEvaluation.report("trial", name, seed, cost, bursts, "revisit", revisit());
                }
            }
        }
    }

    private static List<ScannerDemo.Burst> movingRouter(int seed) {
        var random = new java.util.Random(seed);
        int first = random.nextInt(13) + 1;
        int second = (first - 1 + 1 + random.nextInt(12)) % 13 + 1;
        int move = 6000 + random.nextInt(3000);
        return List.of(new ScannerDemo.Burst(first, random.nextInt(50), move),
                new ScannerDemo.Burst(second, move, 12000));
    }
}
