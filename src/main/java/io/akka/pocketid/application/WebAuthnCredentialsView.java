package io.akka.pocketid.application;

import akka.javasdk.annotations.Component;
import akka.javasdk.annotations.Consume;
import akka.javasdk.annotations.Query;
import akka.javasdk.view.TableUpdater;
import akka.javasdk.view.View;
import io.akka.pocketid.domain.WebAuthnCredentialRecord;
import java.util.List;

@Component(id = "webauthn-credentials-view")
public class WebAuthnCredentialsView extends View {

  public record Credentials(List<WebAuthnCredentialRecord> credentials) {}

  @Consume.FromKeyValueEntity(WebAuthnCredentialEntity.class)
  public static class Updater extends TableUpdater<WebAuthnCredentialRecord> {
    public Effect<WebAuthnCredentialRecord> onUpdate(WebAuthnCredentialRecord state) {
      if (state.id() == null) return effects().ignore();
      return effects().updateRow(state);
    }
  }

  @Query("SELECT * AS credentials FROM webauthn_credentials_view WHERE userId = :userId")
  public QueryEffect<Credentials> byUser(String userId) {
    return queryResult();
  }

  @Query("SELECT * AS credentials FROM webauthn_credentials_view WHERE credentialIdBase64 = :credentialIdBase64")
  public QueryEffect<Credentials> byCredentialId(String credentialIdBase64) {
    return queryResult();
  }
}
