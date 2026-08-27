package io.akka.pocketid.api;

import akka.NotUsed;
import akka.http.javadsl.model.HttpResponse;
import akka.javasdk.http.HttpResponses;
import akka.stream.javadsl.Source;
import java.time.Duration;
import java.util.List;
import java.util.function.Supplier;

/**
 * The stream every admin list screen subscribes to, in place of fetch-on-navigate
 * (RENDERING.md R1). Every frame is the whole current snapshot rather than a delta — the
 * same choice {@code TableStreamEndpoint} makes elsewhere in this harness — so a client that
 * reconnects (browsers retry a dropped {@code EventSource} on their own, satisfying R1.3)
 * needs no replay position: its very next frame is current state.
 */
final class SseSupport {
  private static final Duration TICK = Duration.ofMillis(500);

  private SseSupport() {}

  static <T> HttpResponse stream(Supplier<T> snapshot) {
    Source<T, NotUsed> source =
        Source.tick(Duration.ZERO, TICK, "")
            .map(ignored -> snapshot.get())
            .statefulMapConcat(
                () -> {
                  var previous = new Object[1];
                  return state -> {
                    if (state.equals(previous[0])) return List.of();
                    previous[0] = state;
                    return List.of(state);
                  };
                })
            .mapMaterializedValue(ignored -> NotUsed.getInstance());
    return HttpResponses.serverSentEvents(source);
  }
}
