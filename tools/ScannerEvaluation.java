package ewave.core;

import ewave.capture.PassiveChannelSurvey;
import ewave.core.ScannerDemo.Burst;
import ewave.core.ScannerDemo.Receiver;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/** Compile alongside target/classes. See tools/passive-scanner.md for commands. */
public final class ScannerEvaluation {
    static final String REPORT_HEADER = "split\tworkload\tseed\tcost_ms\tmethod\tcaptured\tmissed\tfound\tundetected\tchanges\tswitch_ms\tdelays_ms";

    static List<Burst> workload(String name, long seed) {
        var rng = new Random(seed);
        var bursts = new ArrayList<Burst>();
        switch (name) {
            case "original", "cold-start" -> { return ScannerDemo.BURSTS; }
            case "continuous" -> bursts.add(new Burst(6, rng.nextInt(50), 12000));
            case "short" -> {
                for (int i = 0; i < 12; i++) {
                    int start = i * 1000 + rng.nextInt(300);
                    bursts.add(new Burst(1 + rng.nextInt(13), start, start + 250 + rng.nextInt(400)));
                }
            }
            case "several" -> {
                var channels = new ArrayList<Integer>();
                for (int ch = 1; ch <= 13; ch++) channels.add(ch);
                java.util.Collections.shuffle(channels, rng);
                for (int i = 0; i < 5; i++) {
                    bursts.add(new Burst(channels.get(i), rng.nextInt(3000), 9000 + rng.nextInt(3000)));
                }
            }
            case "quiet" -> {
                for (int i = 0; i < 2; i++) {
                    int start = 1000 + i * 6000 + rng.nextInt(3500);
                    bursts.add(new Burst(1 + rng.nextInt(13), start, start + 150));
                }
            }
            default -> throw new IllegalArgumentException(name);
        }
        return bursts;
    }

    // Historical selector and survey, retained only as measurement controls.
    private static Receiver old(boolean live) {
        var scanner = new AdaptiveScanner(AdaptiveScanner.Config.defaults(13, 2048, 42));
        return new Receiver() {
            int next = 1, reserved, nextAt = 1000, until;

            public int choose(int now, int current) {
                if (live && reserved != 0 && now < until) return reserved;
                reserved = 0;
                if (live && now >= nextAt) {
                    reserved = next;
                    next = next % 13 + 1;
                    nextAt = now + 1000;
                    until = now + 250;
                    return reserved;
                }
                return scanner.choose(now / 100, 1).bands()[0] + 1;
            }
            public void arrived(int now, int channel, int cost) {
                if (channel == reserved) until = now + 250;
            }
            public void window(int tick, int channel, boolean hit, boolean full, boolean listeningAtEnd) {
                scanner.observe(channel - 1, tick, hit, hit || (live ? listeningAtEnd : full));
            }
        };
    }

    static void report(String split, String workload, int seed, int cost, List<Burst> bursts,
                       String method, Receiver receiver) {
        boolean warm = !workload.equals("cold-start");
        var run = ScannerDemo.simulate(bursts, cost, receiver, warm);
        var delays = new ArrayList<String>();
        int found = 0;
        for (var burst : run.detections()) {
            if (burst.delayMs() != null) found++;
            delays.add(burst.delayMs() == null ? "-" : burst.delayMs().toString());
        }
        long listening = run.dwellMs().stream().mapToLong(Long::longValue).sum();
        System.out.printf("%s\t%s\t%d\t%d\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s%n", split, workload, seed, cost, method,
                run.capturedFrames(), run.missedFrames(), found, bursts.size() - found, run.retunes(),
                12000 - listening - (warm ? 0 : 100), String.join("/", delays));
    }

    public static void main(String[] args) {
        boolean tune = args.length == 1 && args[0].equals("tune");
        System.out.println(REPORT_HEADER);
        for (String name : List.of("original", "cold-start", "continuous", "short", "several", "quiet")) {
            if (tune && name.equals("cold-start")) continue;
            boolean fixture = name.equals("original") || name.equals("cold-start");
            int[] seeds = fixture ? new int[]{42} : tune ? new int[]{1, 2} : new int[]{73, 149, 311};
            for (int seed : seeds) {
                String split = fixture ? "fixture" : tune ? "tune" : "held-out";
                var bursts = workload(name, seed);
                int[] costs = fixture ? new int[]{25} : tune ? new int[]{10, 50} : new int[]{0, 25, 150};
                for (int cost : costs) {
                    if (tune) {
                        for (int limit : new int[]{500, 1200, 2400}) {
                            report(split, name, seed, cost, bursts, "cap" + limit,
                                    ScannerDemo.adaptive(new PassiveChannelSurvey(limit)));
                        }
                    } else {
                        if (name.equals("original")) report(split, name, seed, cost, bursts, "old-demo", old(false));
                        report(split, name, seed, cost, bursts, "old-live", old(true));
                        report(split, name, seed, cost, bursts, "adaptive", ScannerDemo.adaptive(new PassiveChannelSurvey()));
                        // Same minimum dwell and sweep, with frame extensions disabled.
                        var sweep = ScannerDemo.adaptive(new PassiveChannelSurvey());
                        report(split, name, seed, cost, bursts, "min-dwell", new Receiver() {
                            public int choose(int now, int current) { return sweep.choose(now, current); }
                            public void arrived(int now, int channel, int elapsed) { sweep.arrived(now, channel, elapsed); }
                        });
                        report(split, name, seed, cost, bursts, "fixed6", ScannerDemo.fixed());
                        report(split, name, seed, cost, bursts, "round-robin", ScannerDemo.roundRobin());
                    }
                }
            }
        }
    }
}
