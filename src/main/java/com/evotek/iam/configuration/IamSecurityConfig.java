package com.evotek.iam.configuration;

import com.evotek.iam.dto.response.TokenResponse;
import com.evotek.iam.service.common.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.io.IOException;
import java.util.Optional;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class IamSecurityConfig {
    private final JwtDecoder jwtDecoder;
    private final CustomPermissionEvaluator customPermissionEvaluator;
    @Autowired
    private UserService userService;
    @Value("${auth.keycloak-enabled}") boolean keycloakEnabled;
    private final String[] PUBLIC_ENDPOINTS = {
            "/api/users", "/api/auth/login_iam", "api/auth/verify-otp", "/api/auth/forgot-password", "/api/auth/reset-password", "/oauth/**"
    };
    @Autowired
    public IamSecurityConfig(
            @Value("${auth.keycloak-enabled}") boolean keycloakEnabled,
            @Qualifier("keycloakDecoder") Optional<JwtDecoder> keycloakDecoder,
            @Qualifier("selfIdpDecoder") Optional<JwtDecoder> selfIdpDecoder,
            CustomPermissionEvaluator customPermissionEvaluator
    ) {
        this.jwtDecoder = keycloakEnabled ?
                keycloakDecoder.orElseThrow(() -> new IllegalStateException("Keycloak decoder not found")) :
                selfIdpDecoder.orElseThrow(() -> new IllegalStateException("Self IDP decoder not found"));
        this.customPermissionEvaluator = customPermissionEvaluator;
    }


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
                                .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                                .anyRequest().authenticated()
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
                .authorizeHttpRequests(request ->
                        request
                                .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                                .anyRequest().authenticated()
                )
                .oauth2Login(oauth2Login -> oauth2Login
                        .failureHandler(new SimpleUrlAuthenticationFailureHandler())
                        .successHandler(new AuthenticationSuccessHandler() {
                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                                Authentication authentication) throws IOException, ServletException {
                                System.out.println("AuthenticationSuccessHandler invoked");
                                System.out.println("Authentication name: " + authentication.getName());
                                TokenResponse tokenResponse = userService.processOAuthPostLogin(authentication);
                                response.setContentType("application/json");
                                response.setCharacterEncoding("UTF-8");
                                response.getWriter().write(tokenResponse.toString());
                            }
                        })
                )
                .formLogin(Customizer.withDefaults())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwtConfigurer -> jwtConfigurer
                        .decoder(jwtDecoder)
                        .jwtAuthenticationConverter(jwtAuthenticationConverter())
                ))
                .exceptionHandling(exceptionHandlingConfigurer ->
                        exceptionHandlingConfigurer.authenticationEntryPoint(new JwtAuthenticationEntryPoint()))
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


    @Bean
     MethodSecurityExpressionHandler createExpressionHandler() {
        DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
        expressionHandler.setPermissionEvaluator(customPermissionEvaluator);
        return expressionHandler;
    }

}