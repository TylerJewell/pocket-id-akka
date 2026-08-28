package io.akka.pocketid.cli;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.Map;

/**
 * `pocket-id export` / `pocket-id import` / `pocket-id key-rotate` — a standalone command-line
 * client, matching the source's own `backend/internal/cmds/` shape, but driving this port's
 * running service over real HTTP rather than opening the database directly. That difference is
 * forced, not stylistic: {@link io.akka.pocketid.application.UserEntity} and its siblings are
 * only reachable through the running service's {@code ComponentClient}, which requires the JVM
 * that hosts them — there is no separate database file this binary could open on its own the way
 * the source's Go binary opens SQLite/Postgres directly. Run with
 * {@code mvn -o exec:java -Dexec.mainClass=io.akka.pocketid.cli.PocketIdCli
 * -Dexec.args="export --url http://localhost:9127 --session &lt;admin-session-id&gt; --path backup.zip"}.
 */
public final class PocketIdCli {
  private PocketIdCli() {}

  public static void main(String[] args) throws Exception {
    if (args.length == 0) {
      printUsageAndExit();
    }
    Map<String, String> opts = parseOptions(Arrays.copyOfRange(args, 1, args.length));
    String url = require(opts, "url");
    String session = opts.get("session");
    // HTTP/1.1, not the default HTTP/2: the runtime sometimes replies and closes the connection
    // before this client has finished writing the request body (an "early response" -- logged
    // server-side as exactly that), which java.net.http's HTTP/2 layer surfaces as an
    // EOFException even though the request already succeeded. Found by running the export/import
    // round trip against a live service, not by inspection -- the response was correct on the
    // wire every time, only the client-side read of it was flaky under HTTP/2.
    var http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(10)).build();

    switch (args[0]) {
      case "export" -> export(http, url, session, require(opts, "path"));
      case "import" -> importBackup(http, url, session, require(opts, "path"));
      case "key-rotate" -> keyRotate(http, url, session);
      case "encryption-key-rotate" -> encryptionKeyRotate(http, url, session, require(opts, "new-key"));
      default -> printUsageAndExit();
    }
  }

  private static void printUsageAndExit() {
    System.err.println("usage: pocket-id-cli <export|import|key-rotate|encryption-key-rotate> --url <base-url> --session <admin-session-id> [--path <zip-path>] [--new-key <key>]");
    System.exit(2);
  }

  private static Map<String, String> parseOptions(String[] rest) {
    Map<String, String> opts = new HashMap<>();
    for (int i = 0; i < rest.length - 1; i += 2) {
      if (rest[i].startsWith("--")) opts.put(rest[i].substring(2), rest[i + 1]);
    }
    return opts;
  }

  private static String require(Map<String, String> opts, String key) {
    String v = opts.get(key);
    if (v == null) { printUsageAndExit(); }
    return v;
  }

  private static void export(HttpClient http, String url, String session, String path) throws Exception {
    var request = HttpRequest.newBuilder(URI.create(url + "/api/admin/backup/export"))
        .header("X-Session-Id", session).GET().build();
    var response = http.send(request, HttpResponse.BodyHandlers.ofString());
    failIfError(response);
    String base64Zip = extractJsonField(response.body(), "base64Zip");
    Files.write(Path.of(path), Base64.getDecoder().decode(base64Zip));
    System.out.println("Exported to " + path);
  }

  private static void importBackup(HttpClient http, String url, String session, String path) throws Exception {
    byte[] zipBytes = Files.readAllBytes(Path.of(path));
    String base64Zip = Base64.getEncoder().encodeToString(zipBytes);
    var request = HttpRequest.newBuilder(URI.create(url + "/api/admin/backup/import"))
        .header("X-Session-Id", session).header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString("{\"base64Zip\":\"" + base64Zip + "\"}"))
        .build();
    var response = http.send(request, HttpResponse.BodyHandlers.ofString());
    failIfError(response);
    System.out.println("Import result: " + response.body());
  }

  private static void keyRotate(HttpClient http, String url, String session) throws Exception {
    var request = HttpRequest.newBuilder(URI.create(url + "/api/application-configuration/rotate-signing-key"))
        .header("X-Session-Id", session).POST(HttpRequest.BodyPublishers.noBody()).build();
    var response = http.send(request, HttpResponse.BodyHandlers.ofString());
    failIfError(response);
    System.out.println("Key rotated: " + response.body());
  }

  /** `pocket-id encryption-key-rotate`: re-wraps every {@code EncryptedString}-equivalent value
   * from the server's current {@code ENCRYPTION_KEY} to {@code newKey}. Same two-step contract as
   * the source's own command — this only rewraps ciphertext already at rest; the operator still
   * has to set {@code ENCRYPTION_KEY=newKey} in the environment and restart every instance. */
  private static void encryptionKeyRotate(HttpClient http, String url, String session, String newKey) throws Exception {
    var request = HttpRequest.newBuilder(URI.create(url + "/api/application-configuration/rotate-encryption-key"))
        .header("X-Session-Id", session).header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString("{\"newKey\":\"" + newKey + "\"}"))
        .build();
    var response = http.send(request, HttpResponse.BodyHandlers.ofString());
    failIfError(response);
    System.out.println("Encryption key rotated: " + response.body());
  }

  private static void failIfError(HttpResponse<String> response) {
    if (response.statusCode() >= 400) {
      System.err.println("Request failed with HTTP " + response.statusCode() + ": " + response.body());
      System.exit(1);
    }
  }

  private static final ObjectMapper MAPPER = new ObjectMapper();

  /** A regex over a multi-megabyte base64 field recurses once per matched character in Java's
   * backtracking engine and overflows the stack long before the actual limit on {@code path} —
   * found by running the export command against a real service and a non-trivial backup, not
   * by inspection. A real JSON parser has no such depth-proportional-to-input-size behavior. */
  private static String extractJsonField(String json, String field) throws IOException {
    var node = MAPPER.readTree(json).get(field);
    if (node == null) throw new IOException("field \"" + field + "\" not found in response: " + json);
    return node.asText();
  }
}
