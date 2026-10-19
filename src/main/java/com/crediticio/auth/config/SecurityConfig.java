package com.crediticio.auth.config;

import com.crediticio.auth.shared.util.TraceIdFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Duration;
import java.util.List;

/**
 * Matriz de permisos de auth-api (HU10 CA02, CA05): inicio, renovación y cierre de sesión son
 * públicos (los dos últimos protegidos por la cookie y la validación de Origin); el registro de
 * usuarios exige ADMINISTRADOR_RIESGO; todo lo demás se deniega. Sin sesión HTTP: cada petición se
 * autentica con su JWT. El CSRF de Spring se desactiva porque ningún endpoint protegido usa cookies
 * de autenticación; los que usan la cookie de renovación validan Origin (ValidadorOrigen). Swagger solo
 * es público con springdoc habilitado (perfil dev), igual que en scoring-api y evaluation-query-api;
 * si no, sus rutas se deniegan (antes se permitían y respondían 500 por recurso inexistente).
 */
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties({WebProperties.class, CookieRenovacionProperties.class})
public class SecurityConfig {

    public static final String ROL_ADMINISTRADOR = "ADMINISTRADOR_RIESGO";
    private static final String[] RUTAS_SWAGGER = {"/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html"};

    @Value("${springdoc.api-docs.enabled:false}")
    private boolean swaggerHabilitado;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, WebProperties webProperties) throws Exception {
        RespuestaSeguridadJson respuestas = new RespuestaSeguridadJson();
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource(webProperties)))
                .sessionManagement(sesion -> sesion.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(autorizacion -> autorizacion
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/login", "/api/v1/auth/refresh",
                                "/api/v1/auth/logout").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/usuarios").hasRole(ROL_ADMINISTRADOR)
                        .requestMatchers(HttpMethod.GET, "/actuator/health").permitAll()
                        .requestMatchers(RUTAS_SWAGGER).access((autenticacion, contexto) ->
                                new AuthorizationDecision(swaggerHabilitado))
                        .requestMatchers("/error").permitAll()
                        .anyRequest().denyAll())
                .oauth2ResourceServer(recursos -> recursos
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                        .authenticationEntryPoint(respuestas)
                        .accessDeniedHandler(respuestas))
                .exceptionHandling(excepciones -> excepciones
                        .authenticationEntryPoint(respuestas)
                        .accessDeniedHandler(respuestas));
        return http.build();
    }

    /** El claim "role" (un único valor) se convierte en la autoridad ROLE_<rol>. */
    public static JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter autoridades = new JwtGrantedAuthoritiesConverter();
        autoridades.setAuthoritiesClaimName("role");
        autoridades.setAuthorityPrefix("ROLE_");
        JwtAuthenticationConverter convertidor = new JwtAuthenticationConverter();
        convertidor.setJwtGrantedAuthoritiesConverter(autoridades);
        return convertidor;
    }

    private static CorsConfigurationSource corsConfigurationSource(WebProperties webProperties) {
        CorsConfiguration configuracion = new CorsConfiguration();
        configuracion.setAllowedOrigins(webProperties.origenesPermitidos());
        configuracion.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        configuracion.setAllowedHeaders(List.of("Content-Type", "Accept", "Authorization", TraceIdFilter.TRACE_ID_HEADER));
        configuracion.setExposedHeaders(List.of(TraceIdFilter.TRACE_ID_HEADER));
        // necesario para que el navegador envíe la cookie de renovación
        configuracion.setAllowCredentials(true);
        configuracion.setMaxAge(Duration.ofHours(1));
        UrlBasedCorsConfigurationSource fuente = new UrlBasedCorsConfigurationSource();
        fuente.registerCorsConfiguration("/**", configuracion);
        return fuente;
    }
}
