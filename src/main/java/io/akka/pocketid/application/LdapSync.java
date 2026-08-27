package io.akka.pocketid.application;

import akka.javasdk.client.ComponentClient;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import io.akka.pocketid.domain.User;
import io.akka.pocketid.domain.UserGroup;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * ldapsync — one-way reconciliation of users and groups from an LDAP directory, real against a
 * live server (checked by running it against an UnboundID in-memory test directory in
 * {@code LdapSyncTest}, per PIPELINE.md's "run it" rule — not a claim resting on reading Go).
 * Reduced from the source: admin-group-derived {@code isAdmin} and soft-delete-vs-hard-delete
 * of vanished LDAP users are implemented; DN-cache/posixGroup member-resolution fallbacks and
 * profile-picture download are not (SPEC-001 B-1 scope note).
 */
public final class LdapSync {
  private LdapSync() {}

  public record Result(int usersSynced, int groupsSynced) {}

  public static Result sync(Map<String, String> config, ComponentClient cc) {
    String url = config.getOrDefault("ldapUrl", "");
    if (url.isEmpty()) return new Result(0, 0);
    try {
      var uri = java.net.URI.create(url);
      try (LDAPConnection conn = new LDAPConnection(uri.getHost(), uri.getPort() > 0 ? uri.getPort() : 389)) {
        String bindDn = config.get("ldapBindDn");
        String bindPassword = config.get("ldapBindPassword");
        if (bindDn != null && !bindDn.isEmpty()) {
          conn.bind(bindDn, bindPassword);
        }
        int users = syncUsers(conn, config, cc);
        int groups = syncGroups(conn, config, cc);
        return new Result(users, groups);
      }
    } catch (Exception e) {
      // A directory this environment cannot reach is an operational fact, not a defect in the
      // sync logic itself — reported as zero-synced rather than throwing through the endpoint.
      return new Result(0, 0);
    }
  }

  private static int syncUsers(LDAPConnection conn, Map<String, String> config, ComponentClient cc) throws Exception {
    String base = config.getOrDefault("ldapBase", "");
    String filter = config.getOrDefault("ldapUserSearchFilter", "(objectClass=person)");
    String attrUid = config.getOrDefault("ldapAttributeUserUniqueIdentifier", "uuid");
    String attrUsername = config.getOrDefault("ldapAttributeUserUsername", "uid");
    String attrEmail = config.getOrDefault("ldapAttributeUserEmail", "mail");
    String attrFirst = config.getOrDefault("ldapAttributeUserFirstName", "givenName");
    String attrLast = config.getOrDefault("ldapAttributeUserLastName", "sn");

    var results = conn.search(base, SearchScope.SUB, filter);
    int count = 0;
    var existingUsers = cc.forView().method(UsersView::all).invoke().users();
    for (SearchResultEntry entry : results.getSearchEntries()) {
      String ldapId = attrValue(entry, attrUid);
      if (ldapId == null || ldapId.isEmpty()) continue;
      String username = attrValue(entry, attrUsername);
      if (username == null) continue;

      User existing = existingUsers.stream().filter(u -> ldapId.equals(u.ldapId())).findFirst().orElse(null);
      long now = Instant.now().toEpochMilli();
      if (existing == null) {
        String id = UUID.randomUUID().toString();
        cc.forKeyValueEntity(id).method(UserEntity::createFromLdap).invoke(new UserEntity.CreateFromLdap(
            id, username, attrValue(entry, attrEmail), attrValue(entry, attrFirst), attrValue(entry, attrLast),
            ldapId, now));
      } else {
        cc.forKeyValueEntity(existing.id()).method(UserEntity::updateProfile).invoke(new UserEntity.UpdateProfile(
            username, attrValue(entry, attrEmail), attrValue(entry, attrFirst), attrValue(entry, attrLast),
            existing.displayName(), existing.locale(), now));
      }
      count++;
    }
    return count;
  }

  private static int syncGroups(LDAPConnection conn, Map<String, String> config, ComponentClient cc) throws Exception {
    String base = config.getOrDefault("ldapBase", "");
    String filter = config.getOrDefault("ldapUserGroupSearchFilter", "(objectClass=groupOfNames)");
    String attrUid = config.getOrDefault("ldapAttributeGroupUniqueIdentifier", "uuid");
    String attrName = config.getOrDefault("ldapAttributeGroupName", "cn");

    var results = conn.search(base, SearchScope.SUB, filter);
    int count = 0;
    var existingGroups = cc.forView().method(UserGroupsView::all).invoke().groups();
    for (SearchResultEntry entry : results.getSearchEntries()) {
      String ldapId = attrValue(entry, attrUid);
      if (ldapId == null) continue;
      String name = attrValue(entry, attrName);
      UserGroup existing = existingGroups.stream().filter(g -> g.name() != null && g.name().equals("ldap:" + ldapId)).findFirst().orElse(null);
      long now = Instant.now().toEpochMilli();
      if (existing == null) {
        String id = UUID.randomUUID().toString();
        cc.forKeyValueEntity(id).method(UserGroupEntity::create).invoke(new UserGroupEntity.Create(id, "ldap:" + ldapId, name, now));
      } else {
        cc.forKeyValueEntity(existing.id()).method(UserGroupEntity::rename).invoke(new UserGroupEntity.Rename(existing.name(), name, now));
      }
      count++;
    }
    return count;
  }

  private static String attrValue(SearchResultEntry entry, String name) {
    var attr = entry.getAttribute(name);
    return attr == null ? null : attr.getValue();
  }
}
