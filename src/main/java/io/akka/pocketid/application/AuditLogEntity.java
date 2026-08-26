package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.keyvalueentity.KeyValueEntity;
import io.akka.pocketid.domain.AuditLogEntry;

/** audit_log_service.go — one audit-log entry, keyed by its own id (append-only, never updated). */
@Component(id = "audit-log")
public class AuditLogEntity extends KeyValueEntity<AuditLogEntry> {

  public record Record(String id, String event, String userId, String username, String clientName, String ipAddress, String userAgent, long nowMillis) {}

  @Override
  public AuditLogEntry emptyState() {
    return new AuditLogEntry(null, null, null, null, null, null, null, 0);
  }

  public Effect<AuditLogEntry> record(Record cmd) {
    var entry = new AuditLogEntry(cmd.id(), cmd.event(), cmd.userId(), cmd.username(), cmd.clientName(), cmd.ipAddress(), cmd.userAgent(), cmd.nowMillis());
    return effects().updateState(entry).thenReply(entry);
  }
}
