package ewave.capture;

import java.util.concurrent.TimeUnit;

/** Reserves listening windows for channels the score-driven selector might skip. */
final class PassiveChannelSurvey {
    private static final long MIN_LISTEN_NANOS = TimeUnit.MILLISECONDS.toNanos(250);
    private final long intervalNanos;
    private long nextSurveyAt;
    private long listenUntil;
    private int nextChannel = 1;
    private int surveyChannel;

    PassiveChannelSurvey(long now, long tickNanos) {
        intervalNanos = Math.max(TimeUnit.SECONDS.toNanos(1), 2 * tickNanos);
        nextSurveyAt = now + intervalNanos;
    }

    /** Returns zero when the normal score-based selection should run. */
    int channel(long now) {
        if (surveyChannel != 0 && now - listenUntil < 0) return surveyChannel;
        surveyChannel = 0;
        if (now - nextSurveyAt < 0) return 0;

        surveyChannel = nextChannel;
        nextChannel = nextChannel % 13 + 1;
        nextSurveyAt = now + intervalNanos;
        listenUntil = now + MIN_LISTEN_NANOS;
        return surveyChannel;
    }

    /** A survey's listening time starts after tuning, even when the command runs slowly. */
    void tuneFinished(long now, int channel, boolean succeeded) {
        if (surveyChannel != channel) return;
        if (succeeded) listenUntil = now + MIN_LISTEN_NANOS;
        else surveyChannel = 0;
    }
}
