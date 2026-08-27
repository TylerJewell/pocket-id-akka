package io.akka.pocketid.api;

import akka.http.javadsl.model.HttpRequest;
import akka.http.javadsl.model.HttpResponse;
import akka.javasdk.annotations.Acl;
import akka.javasdk.annotations.http.Get;
import akka.javasdk.annotations.http.HttpEndpoint;
import akka.javasdk.http.HttpResponses;

/**
 * Serves pocket-id's own web interface, vendored under {@code gui/webapp/} and built into
 * {@code src/main/resources/static-resources/} (`pnpm build` with
 * {@code BUILD_OUTPUT_PATH=../../src/main/resources/static-resources`, per its own
 * {@code svelte.config.js} adapter-static config).
 *
 * <p>RENDERING.md R3 — this is the original's own SvelteKit app, not a smaller one standing in
 * for it. What the port's data layer changed: the API base path (already {@code /api}, matching
 * the source unchanged) and {@code app-config-service.ts}'s PUT body, wrapped in
 * {@code {values: ...}} because the SDK does not bind a bare JSON object as a top-level request
 * type — see {@code AppConfigEndpoint.ConfigChanges}.
 */
@HttpEndpoint
@Acl(allow = @Acl.Matcher(principal = Acl.Principal.INTERNET))
public class UiEndpoint {

  @Get("/")
  public HttpResponse index() {
    return HttpResponses.staticResource("index.html");
  }

  /**
   * Routing is the SvelteKit app's, not this endpoint's: a path with no static file behind it is
   * one of pocket-id's own client-side routes and gets the shell, so e.g.
   * {@code /settings/admin/users} opens directly rather than only by client-side navigation.
   */
  @Get("/**")
  public HttpResponse asset(HttpRequest request) {
    String path = request.getUri().path();
    // /akka/ is the runtime's own namespace; /api/ is this service's own API. Answering there
    // with the SPA shell would tell the runtime's health check a path it expects absent exists.
    // /authorize excluded too: OidcEndpoint registers a real GET there (the protocol endpoint
    // itself, not a page). /login is NOT excluded here -- OidcEndpoint's GET-vs-POST routing
    // already separates it from that class's @Post("/login") test-login stand-in, and a
    // browser opening /login directly (not just arriving there by client-side navigation from
    // "/") needs the SPA shell the same as any other client-side route.
    if (path.startsWith("/akka/") || path.startsWith("/api/") || path.startsWith("/.well-known/")
        || path.equals("/authorize")) {
      return HttpResponses.notFound();
    }
    if (looksLikeAFile(path)) {
      return HttpResponses.staticResource(request, "/");
    }
    return HttpResponses.staticResource("index.html");
  }

  private static boolean looksLikeAFile(String path) {
    int lastSlash = path.lastIndexOf('/');
    return path.indexOf('.', lastSlash) > -1;
  }
}
