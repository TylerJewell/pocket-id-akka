package io.akka.pocketid.api;

import java.security.SecureRandom;

/** onetimeaccess — token length policy: 6 unambiguous characters for a short-lived (<=15min)
 * link, 12 for a longer-lived one, matching the source's rationale (short tokens are only safe
 * against guessing when the exchange window is also short). */
public final class OneTimeAccess {
  private OneTimeAccess() {}

  private static final String ALPHABET = "BCDFGHJKLMNPQRSTVWXYZ23456789";
  private static final SecureRandom RANDOM = new SecureRandom();

  public static String randomToken(long ttlMillis) {
    int length = ttlMillis <= 15 * 60_000L ? 6 : 12;
    StringBuilder sb = new StringBuilder(length);
    for (int i = 0; i < length; i++) sb.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
    return sb.toString();
  }
}
