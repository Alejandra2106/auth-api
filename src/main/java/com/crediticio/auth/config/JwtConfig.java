package com.crediticio.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.function.Function;

/**
 * Firma RS256 con la clave privada (solo auth-api) y validación local con la clave pública: firma,
 * algoritmo permitido (solo RS256), emisor, audiencia propia y vigencia (HU09 CA05). Las claves se
 * leen de archivos PEM externos; si faltan o son inválidas, la aplicación no arranca.
 */
@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtConfig {

    @Bean
    public JwtEncoder jwtEncoder(JwtProperties propiedades) {
        RSAKey claveRsa = new RSAKey.Builder(leer(propiedades.clavePublica(), RsaKeyConverters.x509()::convert,
                "pública"))
                .privateKey(leer(propiedades.clavePrivada(), RsaKeyConverters.pkcs8()::convert, "privada"))
                .keyID(propiedades.idClave())
                .build();
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(claveRsa)));
    }

    @Bean
    public JwtDecoder jwtDecoder(JwtProperties propiedades) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withPublicKey(leer(propiedades.clavePublica(), RsaKeyConverters.x509()::convert, "pública"))
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(validador(propiedades.emisor(), propiedades.audienciaPropia()));
        return decoder;
    }

    /** Emisor y vigencia (con 60 s de tolerancia de reloj) y que la audiencia incluya esta API. */
    public static OAuth2TokenValidator<Jwt> validador(String emisor, String audiencia) {
        OAuth2TokenValidator<Jwt> audienciaValida = new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
                audiencias -> audiencias != null && audiencias.contains(audiencia));
        return new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(emisor), audienciaValida);
    }

    private static <T> T leer(Resource recurso, Function<InputStream, T> convertidor, String tipo) {
        if (recurso == null || !recurso.exists()) {
            throw new IllegalStateException("No se encontró la clave " + tipo + " del JWT configurada");
        }
        try (InputStream entrada = recurso.getInputStream()) {
            return convertidor.apply(entrada);
        } catch (IOException ex) {
            throw new UncheckedIOException("No fue posible leer la clave " + tipo + " del JWT", ex);
        }
    }
}
