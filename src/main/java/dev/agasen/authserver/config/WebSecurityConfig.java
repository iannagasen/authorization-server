package dev.agasen.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

// Commented for now
// Config is not working when accessing
// http://localhost:8081/.well-known/openid-configuration
// See SpringDocWebSecurityConfig

// @Configuration
public class WebSecurityConfig {
  /**
   * AUTH SERVER manages 2 entities
   * 1. User
   * 2. Client
   * 
   * @throws Exception
   */

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http
        // .formLogin(Customizer.withDefaults())
        .authorizeHttpRequests(t -> t.anyRequest().authenticated())
        // temporary disable to access the openid config uri
        .csrf(c -> c.disable())
        .build();
  }

  @Bean
  public UserDetailsService userDetailsService() {
    // TODO: encode password in prod build, this is for simplicity only
    var u1 = User.withUsername("ian").password("12345").build();

    var uds = new InMemoryUserDetailsManager();
    uds.createUser(u1);

    return uds;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    // TODO: Implement PasswordEncoder
    return NoOpPasswordEncoder.getInstance();
  }
}
