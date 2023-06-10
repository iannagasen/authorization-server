package dev.agasen.authserver.config;

import java.time.Duration;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import dev.agasen.authserver.config.keys.JwksKeys;

// Commented for now
// Config is not working when accessing
// http://localhost:8081/.well-known/openid-configuration
// See SpringDocWebSecurityConfig

// @Configuration
public class AuthorizationServerConfig {

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    return http.formLogin(Customizer.withDefaults()).build();
  }

  /**
   * This is similar to UserDetailsService Contract
   * id - not important
   * client id - the actual id
   * client secret - should be encoded/hash
   * OidScopes.OPENID - we'll follow set of rules from OPENID protocol
   */
  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    // better implementaion is to take all fields from database
    var rc = RegisteredClient
        .withId(UUID.randomUUID().toString())
        .clientId("client")
        .clientSecret("secret")
        .scope(OidcScopes.OPENID) // can be set to "ADMIN", or anything
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)

        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)

        .redirectUri("http://localhost:3000/authorized")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofHours(10))
            .refreshTokenTimeToLive(Duration.ofHours(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(true)
            .build())
        .build();

    // TODO: provide implementation of RegisteredClientRepository
    return new InMemoryRegisteredClientRepository(rc);
  }

  /**
   * AuthorizationServerSettings was previously name ProviderSettings
   */
  @Bean
  public AuthorizationServerSettings providerSettings() {
    return AuthorizationServerSettings.builder().build();
  }

  /**
   * JWT Tokens needs to be signed
   */
  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    RSAKey rsaKey = JwksKeys.generateRsaKey();
    JWKSet set = new JWKSet(rsaKey);
    return (j, sc) -> j.select(set);
  }
}
