package io.akka.pocketid.api;

import io.akka.pocketid.domain.CustomClaim;
import io.akka.pocketid.domain.User;
import io.akka.pocketid.domain.UserGroup;
import java.util.List;

/** JSON shapes matching internal/dto/*.go field names, so the vendored frontend (RENDERING R3)
 * needs no changes beyond its data layer's base URL. */
public final class Dtos {
  private Dtos() {}

  public record UserGroupMinimal(String id, String name, String friendlyName) {}

  public record UserDto(
      String id, String username, String email, boolean emailVerified, String firstName, String lastName,
      String displayName, boolean isAdmin, String locale, List<CustomClaim> customClaims,
      List<UserGroupMinimal> userGroups, String ldapId, boolean disabled) {}

  public static UserDto userDto(User u, List<UserGroup> allGroups, List<CustomClaim> claims) {
    List<UserGroupMinimal> groups = allGroups.stream()
        .filter(g -> u.groupIds().contains(g.id()))
        .map(g -> new UserGroupMinimal(g.id(), g.name(), g.friendlyName()))
        .toList();
    return new UserDto(u.id(), u.username(), u.email(), u.emailVerified(), u.firstName(), u.lastName(),
        u.displayName(), u.isAdmin(), u.locale(), claims == null ? List.of() : claims, groups, u.ldapId(), u.disabled());
  }

  public record UserGroupDto(
      String id, String name, String friendlyName, List<UserMinimal> users, List<CustomClaim> customClaims) {}

  public record UserMinimal(String id, String username, String email, String firstName, String lastName) {}

  public record Page<T>(List<T> data, Pagination pagination) {}

  public record Pagination(int totalItems, int totalPages, int currentPage, int itemsPerPage) {}

  public static <T> Page<T> page(List<T> all) {
    return new Page<>(all, new Pagination(all.size(), 1, 1, Math.max(all.size(), 1)));
  }
}
