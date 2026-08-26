package io.akka.pocketid.api;

import akka.http.javadsl.model.HttpHeader;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.RequestContext;
import io.akka.pocketid.application.AuditLogEntity;
import java.time.Instant;
import java.util.UUID;

/** audit_log_service.go's {@code Create} — records one security-relevant event. */
public final class AuditRecorder {
  private AuditRecorder() {}

  public static void record(ComponentClient cc, RequestContext ctx, String event, String userId, String username, String clientName) {
    String ip = ctx.requestHeader("X-Forwarded-For").map(HttpHeader::value).orElse("unknown");
    String ua = ctx.requestHeader("User-Agent").map(HttpHeader::value).orElse("unknown");
    String id = UUID.randomUUID().toString();
    cc.forKeyValueEntity(id).method(AuditLogEntity::record)
        .invoke(new AuditLogEntity.Record(id, event, userId, username, clientName, ip, ua, Instant.now().toEpochMilli()));
  }
}
