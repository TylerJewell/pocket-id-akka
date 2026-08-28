package io.akka.pocketid.application;

import java.util.LinkedHashMap;
import java.util.Map;

/** appconfig/model.go `getDefaultConfig()` — the default value for every configuration key. */
public final class AppConfigDefaults {
  private AppConfigDefaults() {}

  public static final java.util.Set<String> PUBLIC_KEYS = java.util.Set.of(
      "appName", "homePageUrl", "accentColor", "disableAnimations", "allowOwnAccountEdit",
      "allowUserSignups", "requireUserEmail", "emailOneTimeAccessAsUnauthenticatedEnabled",
      "emailOneTimeAccessAsAdminEnabled", "emailVerificationEnabled", "ldapEnabled");

  public static final java.util.Set<String> SENSITIVE_KEYS = java.util.Set.of("smtpPassword", "ldapBindPassword");

  public static Map<String, String> defaults() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put("appName", "Pocket ID");
    m.put("sessionDuration", "60");
    m.put("homePageUrl", "");
    m.put("emailsVerified", "false");
    m.put("accentColor", "");
    m.put("disableAnimations", "false");
    m.put("allowOwnAccountEdit", "true");
    m.put("allowUserSignups", "disabled");
    m.put("signupDefaultUserGroupIDs", "[]");
    m.put("signupDefaultCustomClaims", "[]");
    m.put("requireUserEmail", "false");
    m.put("smtpHost", "");
    m.put("smtpPort", "");
    m.put("smtpFrom", "");
    m.put("smtpUser", "");
    m.put("smtpPassword", "");
    m.put("smtpTls", "none");
    m.put("smtpSkipCertVerify", "false");
    m.put("emailLoginNotificationEnabled", "false");
    m.put("emailOneTimeAccessAsUnauthenticatedEnabled", "false");
    m.put("emailOneTimeAccessAsAdminEnabled", "false");
    m.put("emailApiKeyExpirationEnabled", "false");
    m.put("emailVerificationEnabled", "false");
    m.put("ldapEnabled", "false");
    m.put("ldapUrl", "");
    m.put("ldapBindDn", "");
    m.put("ldapBindPassword", "");
    m.put("ldapBase", "");
    m.put("ldapUserSearchFilter", "(objectClass=person)");
    m.put("ldapUserGroupSearchFilter", "(objectClass=groupOfNames)");
    m.put("ldapSkipCertVerify", "false");
    m.put("ldapAttributeUserUniqueIdentifier", "uuid");
    m.put("ldapAttributeUserUsername", "uid");
    m.put("ldapAttributeUserEmail", "mail");
    m.put("ldapAttributeUserFirstName", "givenName");
    m.put("ldapAttributeUserLastName", "sn");
    m.put("ldapAttributeUserDisplayName", "displayName");
    m.put("ldapAttributeUserProfilePicture", "jpegPhoto");
    m.put("ldapAttributeGroupMember", "member");
    m.put("ldapAttributeGroupUniqueIdentifier", "uuid");
    m.put("ldapAttributeGroupName", "cn");
    m.put("ldapAdminGroupName", "");
    m.put("ldapSoftDeleteUsers", "true");
    m.put("webauthnUserVerification", "required");
    m.put("webauthnAllowSyncedPasskeys", "true");
    m.put("webauthnAuthenticatorAttachment", "");
    m.put("cimdUrlAllowlist", "[]");
    m.put("disableRateLimiting", "false");
    return m;
  }
}
