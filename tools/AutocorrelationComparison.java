package ewave;

import java.nio.file.*;
import java.util.*;
import org.jtransforms.fft.DoubleFFT_1D;

/** Optional manual comparison; JTransforms is not a library/build dependency. */
public final class AutocorrelationComparison {
    static int[] fft(List<PeriodFit.Sample> samples, int maxPeriod) {
        long first = samples.getFirst().tick();
        int span = Math.toIntExact(samples.getLast().tick() - first + 1);
        int highest = Math.min(maxPeriod,span/3), size = 1;
        while (size < 2*span) size *= 2;
        double[] data = new double[2*size];
        int hits = 0;
        for (var sample : samples) if (sample.detection()) { data[2*Math.toIntExact(sample.tick()-first)] = 1; hits++; }
        double mean = hits/(double)span;
        for (int i=0;i<span;i++) data[2*i] -= mean;
        var fft = new DoubleFFT_1D(size);
        fft.complexForward(data);
        for (int i=0;i<size;i++) { data[2*i] = data[2*i]*data[2*i] + data[2*i+1]*data[2*i+1]; data[2*i+1] = 0; }
        fft.complexInverse(data,true);
        var lags = new ArrayList<Integer>();
        for (int lag=2;lag<=highest;lag++) lags.add(lag);
        lags.sort((a,b)-> { int c=Double.compare(data[2*b],data[2*a]); return c==0 ? Integer.compare(b,a) : c; });
        Set<Integer> candidates = new TreeSet<>();
        for (int lag:lags.stream().limit(4).toList()) { candidates.add(lag); if(lag%2==0 && lag/2>=2) candidates.add(lag/2); }
        return candidates.stream().mapToInt(Integer::intValue).toArray();
    }
    public static void main(String[] args) throws Exception {
        for (String name:List.of("long_period","coupled")) {
            List<PeriodFit.Sample> samples = new ArrayList<>();
            for(String line:Files.readAllLines(Path.of("src/test/resources/reference/"+name+".csv"))) {
                String[] fields=line.split(",");
                if(fields[0].equals("O") && fields[2].equals("0")) samples.add(new PeriodFit.Sample(Long.parseLong(fields[1]),fields[3].equals("1")));
            }
            int max = name.equals("long_period") ? 300:280;
            int[] direct=PeriodFit.autocorrelationCandidates(samples,max), transformed=fft(samples,max);
            if(!Arrays.equals(direct,transformed)) throw new AssertionError(name+" candidates differ");
            for(int i=0;i<100;i++) { PeriodFit.autocorrelationCandidates(samples,max); fft(samples,max); }
            long start=System.nanoTime();
            for(int i=0;i<500;i++) PeriodFit.autocorrelationCandidates(samples,max);
            double directMs=(System.nanoTime()-start)/500e6;
            start=System.nanoTime();
            for(int i=0;i<500;i++) fft(samples,max);
            double fftMs=(System.nanoTime()-start)/500e6;
            System.out.printf(Locale.ROOT,"%s n=%d candidates=%s direct_ms=%.4f fft_ms=%.4f%n",name,samples.size(),Arrays.toString(direct),directMs,fftMs);
        }
        System.exit(0); // JLargeArrays may retain worker threads after the comparison.
    }
}
