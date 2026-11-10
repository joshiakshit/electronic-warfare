package ewave.capture;

import org.junit.jupiter.api.Test;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;

class PassiveChannelSurveyTest {
    @Test void revisitsEveryChannelEvenWhenScoreSelectionKeepsChoosingChannelOne() {
        var survey = new PassiveChannelSurvey(0, MILLISECONDS.toNanos(500));
        assertEquals(0, survey.channel(MILLISECONDS.toNanos(500)));
        for (int visit = 1; visit <= 14; visit++) {
            long start = MILLISECONDS.toNanos(1000L * visit);
            int channel = (visit - 1) % 13 + 1;
            assertEquals(channel, survey.channel(start));
            survey.tuneFinished(start + MILLISECONDS.toNanos(40), channel, true);
            assertEquals(0, survey.channel(start + MILLISECONDS.toNanos(500)));
        }
    }

    @Test void holdsTheChannelAfterASlowTuneAndMovesOnAfterFailure() {
        var survey = new PassiveChannelSurvey(0, MILLISECONDS.toNanos(100));
        assertEquals(1, survey.channel(MILLISECONDS.toNanos(1000)));
        survey.tuneFinished(MILLISECONDS.toNanos(1850), 1, true);
        assertEquals(1, survey.channel(MILLISECONDS.toNanos(2000)));
        assertEquals(2, survey.channel(MILLISECONDS.toNanos(2100)));
        survey.tuneFinished(MILLISECONDS.toNanos(2200), 2, false);
        assertEquals(0, survey.channel(MILLISECONDS.toNanos(2300)));
        assertEquals(3, survey.channel(MILLISECONDS.toNanos(3100)));
    }

    @Test void leavesTimeForScoreBasedSelectionAtSlowTickRates() {
        var survey = new PassiveChannelSurvey(0, MILLISECONDS.toNanos(2000));
        assertEquals(0, survey.channel(MILLISECONDS.toNanos(2000)));
        assertEquals(1, survey.channel(MILLISECONDS.toNanos(4000)));
        survey.tuneFinished(MILLISECONDS.toNanos(4050), 1, true);
        assertEquals(0, survey.channel(MILLISECONDS.toNanos(6000)));
        assertEquals(2, survey.channel(MILLISECONDS.toNanos(8000)));
    }
}
