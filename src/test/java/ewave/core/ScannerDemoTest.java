package ewave.core;

import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class ScannerDemoTest {
    @Test void countsOnlyFramesHeardAfterTuningCompletesAcrossTickBoundaries() {
        for (int cost : new int[]{0, 25, 100, 150, 250}) {
            var arrivals = new ArrayList<Integer>();
            var choices = new ArrayList<Integer>();
            var receiver = new ScannerDemo.Receiver() {
                public int choose(int start, int current) {
                    choices.add(start);
                    return 7;
                }
                public void arrived(int time, int channel, int elapsed) {
                    arrivals.add(time);
                }
            };
            var burst = new ScannerDemo.Burst(7, 100, 500);
            var run = ScannerDemo.simulate(List.of(burst), cost, receiver);
            assertEquals(List.of(0, 100 + cost), arrivals);
            assertTrue(choices.stream().noneMatch(t -> t > 100 && t < 100 + cost));
            assertEquals(12000 - cost, run.dwellMs().stream().mapToLong(Long::longValue).sum());
            assertEquals(1, run.retunes());
            int lost = (cost + 49) / 50;
            assertEquals(lost, run.missedFrames());
            assertEquals(8 - lost, run.capturedFrames());
            assertEquals(lost * 50, run.detections().getFirst().delayMs());
        }
    }
}
