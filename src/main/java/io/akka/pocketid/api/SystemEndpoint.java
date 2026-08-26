package io.akka.pocketid.api;

import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.http.Get;
import akka.javasdk.annotations.http.HttpEndpoint;
import java.util.Map;

/** healthz_controller.go, version_controller.go. */
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.ALL))
@HttpEndpoint("")
public class SystemEndpoint {

  @Get("/healthz")
  public Map<String, String> healthz() {
    return Map.of("status", "healthy");
  }

  @Get("/api/version/current")
  public Map<String, String> current() {
    return Map.of("version", "1.0.0-akka");
  }

  @Get("/api/version/latest")
  public Map<String, String> latest() {
    // version_service.go calls out to GitHub for the latest release; this port does not reach
    // an external network to check that claim by running it (SPEC scope note), so it reports
    // itself as current rather than guessing at an unverified upstream number.
    return Map.of("version", "1.0.0-akka");
  }
}
