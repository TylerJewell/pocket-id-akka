package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.annotations.Consume;
import akka.javasdk.annotations.Query;
import akka.javasdk.view.TableUpdater;
import akka.javasdk.view.View;
import io.akka.pocketid.domain.AuditLogEntry;
import java.util.List;
import java.util.Optional;

@Component(id = "audit-logs-view")
public class AuditLogsView extends View {

  public record Row(
      String id, String event, String userId, Optional<String> username, Optional<String> clientName,
      Optional<String> ipAddress, Optional<String> userAgent, long createdAtMillis) {

    static Row from(AuditLogEntry e) {
      return new Row(e.id(), e.event(), e.userId(), Optional.ofNullable(e.username()), Optional.ofNullable(e.clientName()),
          Optional.ofNullable(e.ipAddress()), Optional.ofNullable(e.userAgent()), e.createdAtMillis());
    }

    AuditLogEntry toEntry() {
      return new AuditLogEntry(id, event, userId, username.orElse(null), clientName.orElse(null),
          ipAddress.orElse(null), userAgent.orElse(null), createdAtMillis);
    }
  }

  public record Entries(List<Row> items) {
    public List<AuditLogEntry> entries() {
      return items.stream().map(Row::toEntry).toList();
    }
  }

  @Consume.FromKeyValueEntity(AuditLogEntity.class)
  public static class Updater extends TableUpdater<Row> {
    public Effect<Row> onUpdate(AuditLogEntry state) {
      if (state.id() == null) return effects().ignore();
      return effects().updateRow(Row.from(state));
    }
  }

  @Query("SELECT * AS items FROM audit_logs_view ORDER BY createdAtMillis DESC")
  public QueryEffect<Entries> all() {
    return queryResult();
  }

  @Query("SELECT * AS items FROM audit_logs_view WHERE userId = :userId ORDER BY createdAtMillis DESC")
  public QueryEffect<Entries> byUser(String userId) {
    return queryResult();
  }
}
