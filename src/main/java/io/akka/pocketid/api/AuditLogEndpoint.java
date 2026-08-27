package io.akka.pocketid.api;

import akka.http.javadsl.model.HttpResponse;
import akka.http.javadsl.model.StatusCodes;
import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.http.Get;
import akka.javasdk.annotations.http.HttpEndpoint;
import akka.javasdk.client.ComponentClient;
import akka.javasdk.http.AbstractHttpEndpoint;
import akka.javasdk.http.HttpResponses;
import io.akka.pocketid.application.AuditLogsView;
import java.util.List;
import java.util.Map;

/** audit_log_controller.go — self can see their own entries, admin can see everyone's. */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.ALL))
@HttpEndpoint("/api")
public class AuditLogEndpoint extends AbstractHttpEndpoint {

  private final ComponentClient cc;

  public AuditLogEndpoint(ComponentClient cc) { this.cc = cc; }

  private static final java.util.Map<String, java.util.Comparator<io.akka.pocketid.domain.AuditLogEntry>> AUDIT_SORT =
      java.util.Map.of(
          "createdAt", java.util.Comparator.comparingLong(io.akka.pocketid.domain.AuditLogEntry::createdAtMillis),
          "event", java.util.Comparator.comparing(io.akka.pocketid.domain.AuditLogEntry::event, String.CASE_INSENSITIVE_ORDER),
          "ipAddress", java.util.Comparator.comparing(io.akka.pocketid.domain.AuditLogEntry::ipAddress, String.CASE_INSENSITIVE_ORDER),
          "device", java.util.Comparator.comparing(io.akka.pocketid.domain.AuditLogEntry::userAgent, String.CASE_INSENSITIVE_ORDER));

  // AuditLogFilter (audit-log.type.ts): userID, event, clientName. `location` (country/city) has
  // no equivalent field on AuditLogEntry, so it is not wired — filterableFields simply omits it,
  // which leaves that one key inert the same way every filter key was before this pass.
  private static final java.util.Map<String, java.util.function.Function<io.akka.pocketid.domain.AuditLogEntry, String>>
      AUDIT_FILTERS = java.util.Map.of(
          "userID", io.akka.pocketid.domain.AuditLogEntry::userId,
          "event", io.akka.pocketid.domain.AuditLogEntry::event,
          "clientName", e -> e.clientName() == null ? "" : e.clientName());

  private boolean auditLogMatches(io.akka.pocketid.domain.AuditLogEntry e, String search) {
    String needle = search.toLowerCase();
    return e.event().toLowerCase().contains(needle)
        || e.username().toLowerCase().contains(needle)
        || (e.clientName() != null && e.clientName().toLowerCase().contains(needle))
        || e.ipAddress().toLowerCase().contains(needle);
  }

  /** Applies search/filters/sort/pagination, defaulting to the view's own newest-first order
   * when no client sort was requested — the view's ORDER BY is what {@code AuditLogsView} always had. */
  private Dtos.Page<io.akka.pocketid.domain.AuditLogEntry> paged(
      java.util.List<io.akka.pocketid.domain.AuditLogEntry> entries, ListQueryParams params) {
    return params.apply(entries, e -> auditLogMatches(e, params.search), AUDIT_SORT, AUDIT_FILTERS);
  }

  @Get("/audit-logs")
  public HttpResponse mine() {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    var entries = cc.forView().method(AuditLogsView::byUser).invoke(u.id()).entries();
    return HttpResponses.ok(paged(entries, ListQueryParams.from(requestContext())));
  }

  @Get("/audit-logs/all")
  public HttpResponse all() {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    if (!u.isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    var entries = cc.forView().method(AuditLogsView::all).invoke().entries();
    return HttpResponses.ok(paged(entries, ListQueryParams.from(requestContext())));
  }

  /** RENDERING.md R1 — the self audit-log screen subscribes to this instead of polling. */
  @Get("/audit-logs/stream")
  public HttpResponse stream() {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    var params = ListQueryParams.from(requestContext());
    return SseSupport.stream(
        () -> paged(cc.forView().method(AuditLogsView::byUser).invoke(u.id()).entries(), params));
  }

  /** RENDERING.md R1 — the global audit-log screen (admin) subscribes to this instead of polling. */
  @Get("/audit-logs/all/stream")
  public HttpResponse allStream() {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    if (!u.isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    var params = ListQueryParams.from(requestContext());
    return SseSupport.stream(() -> paged(cc.forView().method(AuditLogsView::all).invoke().entries(), params));
  }

  @Get("/audit-logs/filters/client-names")
  public HttpResponse clientNames() {
    var entries = cc.forView().method(AuditLogsView::all).invoke().entries();
    List<String> names = entries.stream().map(io.akka.pocketid.domain.AuditLogEntry::clientName)
        .filter(n -> n != null && !n.isEmpty()).distinct().toList();
    return HttpResponses.ok(names);
  }

  @Get("/audit-logs/filters/users")
  public HttpResponse users() {
    var entries = cc.forView().method(AuditLogsView::all).invoke().entries();
    Map<String, String> byId = new java.util.LinkedHashMap<>();
    for (var e : entries) byId.putIfAbsent(e.userId(), e.username());
    return HttpResponses.ok(byId);
  }
}
