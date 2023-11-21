package com.sandbox.Security.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.sandbox.Security.entity.User;
import com.sandbox.Security.util.Jwks;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.sql.DataSource;

@Configuration
public class AuthConfig {

    private RSAKey rsaKey;
    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource) throws Exception {
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource){{
            setUsersByUsernameQuery("SELECT username, password, active FROM User WHERE username = ?");
            setAuthoritiesByUsernameQuery("SELECT username, name FROM User u JOIN Role r ON u.roleid = r.id WHERE username = ?");
        }};
        return manager;
    }

//    @Bean
//    public UserDetailsManager inMemoryUsers() throws Exception {
//        return new InMemoryUserDetailsManager(org.springframework.security.core.userdetails.User.builder()
//                .username("novke")
//                .password("{noop}123")
//                .roles("ADMIN", "USER")
//                .build());
//    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        Customizer customizer = Customizer.withDefaults();

        http.authorizeHttpRequests(authz ->
                authz.requestMatchers(HttpMethod.GET, "/users").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(HttpMethod.GET, "/admin").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.GET, "/all").permitAll()
                        .requestMatchers(HttpMethod.POST,"/token").permitAll()
                        .anyRequest().authenticated()) //mora bilo koji korisnik
                .oauth2ResourceServer(configurer -> configurer.jwt(customizer))
//                .csrf().disable()             //DEPRECATED
                .csrf(AbstractHttpConfigurer::disable) //OBAVEZNO! zaustavlja post metode!!!
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(customizer); //http basic ide samo na token ??
        /////////// IZ NEKOG RAZLOGA NE RADI AKO SE ISKLJUCI HHTPBASIC ???

        return http.build();
    }

    /////////////// FILTER CHAIN ZA TOKEN GENERATOR //////////////////
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Bean
    SecurityFilterChain tokenFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/token")
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/token").permitAll())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(Customizer.withDefaults())
                .build();
    }

//    @Bean
//    CorsConfigurationSource corsConfigurationSource() {
//        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
//        return source;
//    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(){
        rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return ((jwkSelector, securityContext) -> jwkSelector.select(jwkSet));
    }

    @Bean
    JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwks){
        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    JwtDecoder jwtDecoder() throws JOSEException{
        return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
    }

    //KAD SE DODA OVO NE TREBA PREFIX {bcrypt} I NE PRIHVATA {noop}
    @Bean
    BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    ////////////////////////////////////////////////////////////////////////////////////
    // "FILTER USER DATA FROM JWT TOKEN"
    //
    // PREDPOSTAVLJAM DA OVO NE TREBA AKO SAM DEFINISAO QUERY-je ZA JDBCUSERSMANAGER ??
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter(){
        final JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthoritiesClaimName("roles"); //OVO MORA DA SE POKLOPI S ONIM IZ TokenService-a
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

        final JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }



}
