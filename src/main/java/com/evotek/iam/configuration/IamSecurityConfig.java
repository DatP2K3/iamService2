package com.evotek.iam.configuration;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Optional;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class IamSecurityConfig {
    private JwtDecoder jwtDecoder;

    @Autowired
    public IamSecurityConfig(
            @Value("${auth.keycloak-enabled}") boolean keycloakEnabled,
            @Qualifier("keycloakDecoder") Optional<JwtDecoder> keycloakDecoder,
            @Qualifier("selfIdpDecoder") Optional<JwtDecoder> selfIdpDecoder
    ) {
        this.jwtDecoder = keycloakEnabled ?
                keycloakDecoder.orElseThrow(() -> new IllegalStateException("Keycloak decoder not found")) :
                selfIdpDecoder.orElseThrow(() -> new IllegalStateException("Self IDP decoder not found"));
    }

    private final String[] PUBLIC_ENDPOINTS = {"/register", "/profiles", "/refresh"};
    @Value("${auth.keycloak-enabled}")
    private boolean keycloakEnabled;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        if (keycloakEnabled) {
            configureKeycloak(httpSecurity);
        } else {
            configureJwt(httpSecurity);
        }
        return httpSecurity.build();
    }

    // Cấu hình khi Keycloak được bật
    private void configureKeycloak(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeHttpRequests(request ->
                        request
                                //.requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                                //.anyRequest().authenticated()
                                .anyRequest().permitAll()
                )
                .httpBasic(Customizer.withDefaults())
                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(Customizer.withDefaults())
                )
                .csrf(AbstractHttpConfigurer::disable);
    }

    // Cấu hình khi Keycloak bị tắt, sử dụng JWT
    private void configureJwt(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeHttpRequests(request -> request
                        //.requestMatchers(HttpMethod.DELETE, "/api/users/**").hasRole("ADMIN") // Quyền ADMIN cho endpoint xóa người dùng
                        .anyRequest().permitAll() // Các endpoint khác được phép truy cập công khai
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwtConfigurer -> jwtConfigurer
                        .decoder(jwtDecoder) // Sử dụng CustomJwtDecoder khi JWT độc lập
                        .jwtAuthenticationConverter(jwtAuthenticationConverter())
                ))
                .exceptionHandling(exceptionHandlingConfigurer ->
                        exceptionHandlingConfigurer.authenticationEntryPoint(new JwtAuthenticationEntryPoint())) // Cấu hình entry point cho JWT
                .csrf(AbstractHttpConfigurer::disable);
    }

    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();

        corsConfiguration.addAllowedOrigin("*");
        corsConfiguration.addAllowedMethod("*");
        corsConfiguration.addAllowedHeader("*");

        UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);

        return new CorsFilter(urlBasedCorsConfigurationSource);
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);

        return jwtAuthenticationConverter;
    }
}