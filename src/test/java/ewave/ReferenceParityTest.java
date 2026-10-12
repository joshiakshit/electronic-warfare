package ewave;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class ReferenceParityTest {
    @ParameterizedTest
    @ValueSource(strings={"sparse_periodic","aperiodic","cw_quiet","bursty","long_period","coupled"})
    void frozenPythonReference(String name) throws IOException {
        AdaptiveScanner scanner = null;
        int lineNumber = 0;
        try (var input = new BufferedReader(new InputStreamReader(Objects.requireNonNull(getClass().getResourceAsStream("/reference/" + name + ".csv")),StandardCharsets.UTF_8))) {
            String line;
            while ((line = input.readLine()) != null) {
                lineNumber++;
                String[] f = line.split(",",-1);
                String context = name + ":" + lineNumber;
                switch (f[0]) {
                    case "C" -> {
                        var base = AdaptiveScanner.Config.defaults(Integer.parseInt(f[1]),Integer.parseInt(f[2]),42);
                        scanner = new AdaptiveScanner(new AdaptiveScanner.Config(base.bands(),base.capacity(),48,6,1,4,Integer.parseInt(f[3]),.9,.01,.3,.03,1,42));
                    }
                    case "O" -> scanner.observe(Integer.parseInt(f[2]),Long.parseLong(f[1]),f[3].equals("1"));
                    case "G" -> {
                        var s = scanner.snapshot(Long.parseLong(f[1]));
                        assertEquals(Integer.parseInt(f[2]),s.coupledPeriod(),context);
                        int[] members = f[3].isEmpty() ? new int[0] : Arrays.stream(f[3].split(":")).mapToInt(Integer::parseInt).toArray();
                        assertArrayEquals(members,s.coupledMembers(),context);
                    }
                    case "Q" -> {
                        int band = Integer.parseInt(f[2]);
                        var s = scanner.snapshot(Long.parseLong(f[1]));
                        assertEquals(Integer.parseInt(f[3]),s.periods()[band],context + " period");
                        assertEquals(Double.parseDouble(f[4]),s.means()[band],1e-9,context + " mean");
                        assertEquals(Double.parseDouble(f[5]),s.spreads()[band],1e-9,context + " spread");
                        assertEquals(Double.parseDouble(f[6]),s.scores()[band],1e-9,context + " score");
                        assertEquals(Double.parseDouble(f[7]),scanner.likelihood(band),1e-9,context + " likelihood");
                    }
                    case "D" -> assertEquals(Integer.parseInt(f[2]),scanner.choose(Long.parseLong(f[1]),1).bands()[0],context + " selection");
                    default -> fail(context + " unknown fixture row");
                }
            }
        }
        // Reset after every fixture, including the established coupled group.
        scanner.reset();
        var fresh = new AdaptiveScanner(scanner.config());
        var reset = scanner.snapshot(0);
        assertArrayEquals(fresh.snapshot(0).scores(),reset.scores());
        assertArrayEquals(new long[scanner.config().bands()],reset.counts());
        assertArrayEquals(new int[scanner.config().bands()],reset.periods());
        assertEquals(0,reset.coupledPeriod());
        assertArrayEquals(new int[0],reset.coupledMembers());
        assertArrayEquals(fresh.choose(0,scanner.config().bands()).bands(),scanner.choose(0,scanner.config().bands()).bands());
    }
}
