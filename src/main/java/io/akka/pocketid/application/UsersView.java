package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.annotations.Consume;
import akka.javasdk.annotations.Query;
import akka.javasdk.view.TableUpdater;
import akka.javasdk.view.View;
import io.akka.pocketid.domain.User;
import java.util.List;
import java.util.Optional;

@Component(id = "users-view")
public class UsersView extends View {

  /** email/locale/ldapId are nullable on {@link User}; a view row field must be declared
   * {@code Optional} whenever a row can be written without it (AK-00111). */
  public record Row(
      String id, String username, Optional<String> email, boolean emailVerified, String firstName, String lastName,
      Optional<String> displayName, boolean isAdmin, Optional<String> locale, boolean disabled, Optional<String> ldapId,
      List<String> groupIds, long createdAtMillis, long updatedAtMillis) {

    static Row from(User u) {
      return new Row(u.id(), u.username(), Optional.ofNullable(u.email()), u.emailVerified(), u.firstName(), u.lastName(),
          Optional.ofNullable(u.displayName()), u.isAdmin(), Optional.ofNullable(u.locale()), u.disabled(), Optional.ofNullable(u.ldapId()),
          u.groupIds(), u.createdAtMillis(), u.updatedAtMillis());
    }

    User toUser() {
      return new User(id, username, email.orElse(null), emailVerified, firstName, lastName, displayName.orElse(null), isAdmin,
          locale.orElse(null), disabled, ldapId.orElse(null), groupIds, createdAtMillis, updatedAtMillis);
    }
  }

  public record Users(List<Row> items) {
    public List<User> users() {
      return items.stream().map(Row::toUser).toList();
    }
  }

  @Consume.FromKeyValueEntity(UserEntity.class)
  public static class Updater extends TableUpdater<Row> {
    public Effect<Row> onUpdate(User state) {
      if (state.id() == null) return effects().ignore();
      return effects().updateRow(Row.from(state));
    }
  }

  @Query("SELECT * AS items FROM users_view")
  public QueryEffect<Users> all() {
    return queryResult();
  }

  @Query("SELECT * AS items FROM users_view WHERE username = :username")
  public QueryEffect<Users> byUsername(String username) {
    return queryResult();
  }

  @Query("SELECT * AS items FROM users_view WHERE email = :email")
  public QueryEffect<Users> byEmail(String email) {
    return queryResult();
  }

  @Query("SELECT * AS items FROM users_view WHERE ldapId = :ldapId")
  public QueryEffect<Users> byLdapId(String ldapId) {
    return queryResult();
  }
}
