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

  @Get("/audit-logs")
  public HttpResponse mine() {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    var entries = cc.forView().method(AuditLogsView::byUser).invoke(u.id()).entries();
    return HttpResponses.ok(Dtos.page(entries));
  }

  @Get("/audit-logs/all")
  public HttpResponse all() {
    var u = AuthSupport.authenticatedUser(requestContext(), cc);
    if (u == null) return HttpResponses.ok(Map.of("error", "unauthorized")).withStatus(StatusCodes.UNAUTHORIZED);
    if (!u.isAdmin()) return HttpResponses.ok(Map.of("error", "forbidden")).withStatus(StatusCodes.FORBIDDEN);
    var entries = cc.forView().method(AuditLogsView::all).invoke().entries();
    return HttpResponses.ok(Dtos.page(entries));
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
