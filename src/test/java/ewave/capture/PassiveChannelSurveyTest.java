package ewave.capture;

import org.junit.jupiter.api.Test;

import java.util.List;

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

    @Test void busySixGhzChannelOneDoesNotExtendTwoPointFourGhzChannelOne() {
        var survey = new PassiveChannelSurvey(List.of(2412, 5260, 5955), 1200);
        survey.tuneFinished(0, 2412, true, 0);
        survey.frame(ms(90), 5955);
        assertEquals(5260, survey.channel(ms(100)));
        survey.tuneFinished(ms(110), 5260, false, 0);
        assertEquals(5955, survey.channel(ms(110)));
        survey.tuneFinished(ms(120), 5955, true, 0);
        survey.frame(ms(200), 5955);
        assertEquals(5955, survey.channel(ms(399)));
        assertEquals(2412, survey.channel(ms(400)));
    }
}
