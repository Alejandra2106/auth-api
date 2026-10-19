package com.crediticio.auth.config;

import com.crediticio.auth.support.ClavesRsaPrueba;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * HU10, P-HU10-03: auth-api valida sus propios tokens con el contrato común (exp obligatorio, sub con
 * formato UUID y role de texto), igual que scoring-api y evaluation-query-api. Antes solo comprobaba
 * emisor, audiencia y vigencia, y aceptaba tokens sin exp, con un sub arbitrario o sin role.
 */
class JwtConfigValidadorTest {

    private static final List<String> AUDIENCIAS = List.of("auth-api", "scoring-api", "evaluation-query-api");
    private static final JwtConfig CONFIG = new JwtConfig();

    @TempDir
    static Path claves;

    private static JwtEncoder encoder;
    private static JwtDecoder decoder;

    @BeforeAll
    static void configurar() {
        ClavesRsaPrueba.escribirPem(ClavesRsaPrueba.generar(), claves);
        JwtProperties propiedades = new JwtProperties("auth-api", AUDIENCIAS, "auth-api", "clave-prueba",
                new FileSystemResource(claves.resolve("clave-privada.pem")),
                new FileSystemResource(claves.resolve("clave-publica.pem")), Duration.ofMinutes(15));
        encoder = CONFIG.jwtEncoder(propiedades);
        decoder = CONFIG.jwtDecoder(propiedades);
    }

    private static JwtClaimsSet.Builder validos() {
        Instant ahora = Instant.now();
        return JwtClaimsSet.builder()
                .issuer("auth-api")
                .audience(AUDIENCIAS)
                .subject(UUID.randomUUID().toString())
                .claim("role", "ADMINISTRADOR_RIESGO")
                .issuedAt(ahora)
                .expiresAt(ahora.plusSeconds(900))
                .id(UUID.randomUUID().toString());
    }

    private static String firmar(JwtClaimsSet claims) {
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims))
                .getTokenValue();
    }

    @Test
    void debeAceptarUnTokenConElContratoComun() {
        assertThat(decoder.decode(firmar(validos().build())).getClaimAsString("role")).isEqualTo("ADMINISTRADOR_RIESGO");
    }

    @Test
    void debeRechazarUnTokenSinExp() {
        Instant ahora = Instant.now();
        JwtClaimsSet sinExp = JwtClaimsSet.builder().issuer("auth-api").audience(AUDIENCIAS)
                .subject(UUID.randomUUID().toString()).claim("role", "ANALISTA_CREDITO").issuedAt(ahora).build();

        assertThatThrownBy(() -> decoder.decode(firmar(sinExp))).isInstanceOf(JwtValidationException.class);
    }

    @Test
    void debeRechazarUnSujetoQueNoEsUuid() {
        assertThatThrownBy(() -> decoder.decode(firmar(validos().subject("admin").build())))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void debeRechazarUnTokenSinRolOConRolVacio() {
        Instant ahora = Instant.now();
        JwtClaimsSet sinRol = JwtClaimsSet.builder().issuer("auth-api").audience(AUDIENCIAS)
                .subject(UUID.randomUUID().toString()).issuedAt(ahora).expiresAt(ahora.plusSeconds(900)).build();

        assertThatThrownBy(() -> decoder.decode(firmar(sinRol))).isInstanceOf(JwtValidationException.class);
        assertThatThrownBy(() -> decoder.decode(firmar(validos().claim("role", " ").build())))
                .isInstanceOf(JwtValidationException.class);
    }
}
