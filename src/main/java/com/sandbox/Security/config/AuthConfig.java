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
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
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
                .httpBasic(customizer);

        return http.build();
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

}
