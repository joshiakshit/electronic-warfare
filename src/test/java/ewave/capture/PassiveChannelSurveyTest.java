package ewave.capture;

import org.junit.jupiter.api.Test;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;

class PassiveChannelSurveyTest {
    private static long ms(int time) { return MILLISECONDS.toNanos(time); }

    @Test void sweepsInOrderEvenWhenEveryChannelStaysBusy() {
        var survey = new PassiveChannelSurvey();
        int time = 0;
        for (int visit = 0; visit < 26; visit++) {
            int channel = visit % 13 + 1;
            assertEquals(channel, survey.channel(ms(time)));
            time += 25;
            survey.tuneFinished(ms(time), channel, true, ms(25));
            for (int elapsed = 0; elapsed < 1200; elapsed += 100) {
                survey.frame(ms(time + elapsed), channel);
                assertEquals(channel, survey.channel(ms(time + elapsed)));
            }
            time += 1200;
        }
    }

    @Test void listensAfterCompletionAndMovesOnAfterFailure() {
        var survey = new PassiveChannelSurvey();
        survey.tuneFinished(ms(800), 13, true, ms(300));
        assertEquals(13, survey.channel(ms(1299)));
        assertEquals(1, survey.channel(ms(1300)));
        survey.tuneFinished(ms(1700), 1, false, ms(400));
        assertEquals(2, survey.channel(ms(1700)));
    }

    @Test void extendsOnlyForRecentActivityOnTheConfirmedChannel() {
        var survey = new PassiveChannelSurvey();
        survey.tuneFinished(0, 4, true, ms(25));
        assertEquals(4, survey.channel(ms(99)));
        survey.frame(ms(80), 4);
        assertEquals(4, survey.channel(ms(279)));
        survey.frame(ms(279), 3);
        assertEquals(5, survey.channel(ms(280)));
        survey.tuneFinished(ms(305), 5, true, ms(25));
        assertEquals(6, survey.channel(ms(405)));
    }
}
