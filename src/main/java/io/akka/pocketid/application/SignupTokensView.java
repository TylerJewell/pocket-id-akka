package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.annotations.Consume;
import akka.javasdk.annotations.Query;
import akka.javasdk.view.TableUpdater;
import akka.javasdk.view.View;
import io.akka.pocketid.domain.SignupToken;
import java.util.List;

@Component(id = "signup-tokens-view")
public class SignupTokensView extends View {

  public record Tokens(List<SignupToken> tokens) {}

  @Consume.FromKeyValueEntity(SignupTokenEntity.class)
  public static class Updater extends TableUpdater<SignupToken> {
    public Effect<SignupToken> onUpdate(SignupToken state) {
      if (state.id() == null) return effects().ignore();
      return effects().updateRow(state);
    }
  }

  @Query("SELECT * AS tokens FROM signup_tokens_view")
  public QueryEffect<Tokens> all() {
    return queryResult();
  }

  @Query("SELECT * AS tokens FROM signup_tokens_view WHERE token = :token")
  public QueryEffect<Tokens> byToken(String token) {
    return queryResult();
  }
}
