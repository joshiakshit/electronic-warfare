package ewave;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

/** Finite recorded-observation inspection. Does not invent outcomes for selected bands. */
public final class Main {
    private Main() {}
    public static void main(String[] args) { System.exit(run(args,System.out,System.err)); }
    static int run(String[] args, PrintStream out, PrintStream err) {
        if (args.length == 1 && args[0].equals("--help")) {
            out.println("Usage: java -jar adaptive-scanner.jar replay BANDS CAPACITY SEED INPUT.csv");
            out.println("Input: tick,band,detection,valid (header optional; bits are 0 or 1).");
            out.println("Output: next_tick,selected_band,score,period. Replay inspects recorded observations; it does not measure counterfactual performance.");
            return 0;
        }
        if (args.length != 5 || !args[0].equals("replay")) { err.println("Use --help for usage"); return 2; }
        try {
            var config = AdaptiveScanner.Config.defaults(Integer.parseInt(args[1]),Integer.parseInt(args[2]),Long.parseLong(args[3]));
            var scanner = new AdaptiveScanner(config);
            out.println("next_tick,selected_band,score,period");
            try (Reader input = Files.newBufferedReader(Path.of(args[4]),StandardCharsets.UTF_8)) {
                String line;
                int lineNumber = 0;
                while ((line = boundedLine(input)) != null) {
                    lineNumber++;
                    if (lineNumber == 1 && line.equals("tick,band,detection,valid")) continue;
                    try {
                        String[] fields = line.split(",",-1);
                        if (fields.length != 4) throw new IllegalArgumentException("Expected four fields");
                        long tick = Long.parseLong(fields[0]); int band = Integer.parseInt(fields[1]);
                        scanner.observe(band,tick,bit(fields[2]),bit(fields[3]));
                        var decision = scanner.choose(tick + 1,1);
                        int selected = decision.bands()[0];
                        out.println((tick + 1) + "," + selected + "," + decision.snapshot().scores()[selected] + "," + decision.snapshot().periods()[selected]);
                    } catch (IllegalArgumentException e) { throw new IllegalArgumentException("Line " + lineNumber + ": " + e.getMessage(),e); }
                }
            }
            if (out.checkError()) throw new IOException("Output write failed");
            return 0;
        } catch (IllegalArgumentException | IOException e) { err.println(e.getMessage()); return e instanceof IOException ? 1 : 2; }
    }
    private static boolean bit(String text) {
        if (!text.equals("0") && !text.equals("1")) throw new IllegalArgumentException("Detection and valid must be 0 or 1");
        return text.equals("1");
    }
    private static String boundedLine(Reader reader) throws IOException {
        StringBuilder line = new StringBuilder();
        int c;
        while ((c = reader.read()) != -1 && c != '\n') {
            if (line.length() >= 256) throw new IllegalArgumentException("Input line exceeds 256 characters");
            line.append((char)c);
        }
        if (c == -1 && line.isEmpty()) return null;
        if (!line.isEmpty() && line.charAt(line.length() - 1) == '\r') line.setLength(line.length() - 1);
        return line.toString();
    }
}
