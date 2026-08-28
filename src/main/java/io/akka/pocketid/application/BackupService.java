package io.akka.pocketid.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.akka.pocketid.domain.ApiKeyRecord;
import io.akka.pocketid.domain.OidcClient;
import io.akka.pocketid.domain.User;
import io.akka.pocketid.domain.UserGroup;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * `export_service.go`/`import_service.go`'s equivalent: a ZIP holding one JSON entry per
 * collection this port manages. Narrower than the source in two named ways (SPEC-001 §1,
 * README's "Where it differs"): no uploaded-file bytes (this port's own images/logos/pictures
 * are content-addressed through {@link FileStorage}, not enumerable without walking every blob
 * key, which this port has no index of), and no actor-host binary state (`francis.bin`) since
 * there is no Francis-shaped actor runtime under this port to snapshot. Every relational
 * record the source's own DB dump covers — users, groups, OIDC clients, API keys, app
 * configuration — is included, in full, not a sample.
 */
public final class BackupService {
  private BackupService() {}

  private static final ObjectMapper MAPPER = new ObjectMapper();

  public record Bundle(
      Map<String, String> config, List<User> users, List<UserGroup> groups,
      List<OidcClient> clients, List<ApiKeyRecord> apiKeys) {}

  public static byte[] toZip(Bundle bundle) {
    try {
      var out = new ByteArrayOutputStream();
      try (var zip = new ZipOutputStream(out)) {
        writeEntry(zip, "config.json", bundle.config());
        writeEntry(zip, "users.json", bundle.users());
        writeEntry(zip, "groups.json", bundle.groups());
        writeEntry(zip, "clients.json", bundle.clients());
        writeEntry(zip, "api-keys.json", bundle.apiKeys());
      }
      return out.toByteArray();
    } catch (IOException e) {
      throw new IllegalStateException("failed to build backup zip", e);
    }
  }

  private static void writeEntry(ZipOutputStream zip, String name, Object value) throws IOException {
    zip.putNextEntry(new ZipEntry(name));
    zip.write(MAPPER.writeValueAsBytes(value));
    zip.closeEntry();
  }

  public static Bundle fromZip(byte[] zipBytes) {
    try {
      Map<String, byte[]> entries = new java.util.HashMap<>();
      try (var zip = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {
        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
          entries.put(entry.getName(), zip.readAllBytes());
        }
      }
      Map<String, String> config = entries.containsKey("config.json")
          ? MAPPER.readValue(entries.get("config.json"), Map.class) : Map.of();
      List<User> users = readList(entries, "users.json", User.class);
      List<UserGroup> groups = readList(entries, "groups.json", UserGroup.class);
      List<OidcClient> clients = readList(entries, "clients.json", OidcClient.class);
      List<ApiKeyRecord> apiKeys = readList(entries, "api-keys.json", ApiKeyRecord.class);
      return new Bundle(config, users, groups, clients, apiKeys);
    } catch (IOException e) {
      throw new IllegalArgumentException("not a valid backup zip", e);
    }
  }

  private static <T> List<T> readList(Map<String, byte[]> entries, String name, Class<T> type) throws IOException {
    if (!entries.containsKey(name)) return new ArrayList<>();
    var factory = MAPPER.getTypeFactory().constructCollectionType(List.class, type);
    return MAPPER.readValue(entries.get(name), factory);
  }
}
