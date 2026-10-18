package com.crediticio.auth.sesiones.infrastructure.output;

import com.crediticio.auth.config.JwtConfig;
import com.crediticio.auth.config.JwtProperties;
import com.crediticio.auth.config.SecurityConfig;
import com.crediticio.auth.sesiones.domain.TokenAcceso;
import com.crediticio.auth.support.ClavesRsaPrueba;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** HU09 CA03–CA05: emisión real con RS256 y validación estricta del contrato JWT común. */
class JwtTokenAccesoTest {

    private static final List<String> AUDIENCIAS = List.of("auth-api", "scoring-api", "evaluation-query-api");

    @TempDir
    static Path claves;

    @TempDir
    static Path otrasClaves;

    private static final JwtConfig CONFIG = new JwtConfig();

    @BeforeAll
    static void generarClaves() {
        ClavesRsaPrueba.escribirPem(ClavesRsaPrueba.generar(), claves);
        ClavesRsaPrueba.escribirPem(ClavesRsaPrueba.generar(), otrasClaves);
    }

    private static JwtProperties propiedades(Path directorio, String emisor, List<String> audiencias) {
        return new JwtProperties(emisor, audiencias, "auth-api", "clave-2026-10",
                new FileSystemResource(directorio.resolve("clave-privada.pem")),
                new FileSystemResource(directorio.resolve("clave-publica.pem")), Duration.ofMinutes(15));
    }

    private static TokenAcceso emitir(JwtProperties propiedades, Clock clock, UUID idUsuario, String rol) {
        return new JwtEmisorTokenAccesoAdapter(CONFIG.jwtEncoder(propiedades), propiedades, clock).emitir(idUsuario, rol);
    }

    private static JwtDecoder decoder() {
        return CONFIG.jwtDecoder(propiedades(claves, "auth-api", AUDIENCIAS));
    }

    @Test
    void debeEmitirRs256ConKidYLosClaimsDelContratoComun() throws Exception {
        UUID idUsuario = UUID.randomUUID();
        TokenAcceso token = emitir(propiedades(claves, "auth-api", AUDIENCIAS), Clock.systemUTC(), idUsuario,
                "ANALISTA_CREDITO");

        Jwt jwt = decoder().decode(token.valor());

        assertThat(token.expiraEnSegundos()).isEqualTo(900);
        assertThat(jwt.getHeaders()).containsEntry("alg", "RS256").containsEntry("kid", "clave-2026-10");
        // "iss" es un StringOrURI (RFC 7519): "auth-api" no es una URL, por eso se lee como texto
        assertThat(jwt.getClaimAsString("iss")).isEqualTo("auth-api");
        assertThat(jwt.getAudience()).containsExactlyElementsOf(AUDIENCIAS);
        assertThat(jwt.getSubject()).isEqualTo(idUsuario.toString());
        assertThat(jwt.getClaimAsString("role")).isEqualTo("ANALISTA_CREDITO");
        assertThat(jwt.getId()).isNotBlank();
        assertThat(Duration.between(jwt.getIssuedAt(), jwt.getExpiresAt())).isEqualTo(Duration.ofMinutes(15));
        assertThat(jwt.getClaims()).doesNotContainKeys("email", "correo");
        assertThat(SignedJWT.parse(token.valor()).getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    }

    @Test
    void elClaimRoleDebeConvertirseEnLaAutoridadDelRol() {
        TokenAcceso token = emitir(propiedades(claves, "auth-api", AUDIENCIAS), Clock.systemUTC(), UUID.randomUUID(),
                "ADMINISTRADOR_RIESGO");

        AbstractAuthenticationToken autenticacion = SecurityConfig.jwtAuthenticationConverter()
                .convert(decoder().decode(token.valor()));

        // Spring Security 7 añade además una autoridad técnica de factor (FACTOR_*); el rol debe ser único
        assertThat(autenticacion.getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .filteredOn(autoridad -> autoridad.startsWith("ROLE_"))
                .containsExactly("ROLE_ADMINISTRADOR_RIESGO");
    }

    @Test
    void debeRechazarUnTokenExpirado() {
        Clock haceUnaHora = Clock.fixed(Instant.now().minus(Duration.ofHours(1)), ZoneOffset.UTC);
        TokenAcceso token = emitir(propiedades(claves, "auth-api", AUDIENCIAS), haceUnaHora, UUID.randomUUID(),
                "ANALISTA_CREDITO");

        assertThatThrownBy(() -> decoder().decode(token.valor())).isInstanceOf(JwtException.class);
    }

    @Test
    void debeRechazarOtroEmisor() {
        TokenAcceso token = emitir(propiedades(claves, "otro-emisor", AUDIENCIAS), Clock.systemUTC(), UUID.randomUUID(),
                "ANALISTA_CREDITO");

        assertThatThrownBy(() -> decoder().decode(token.valor())).isInstanceOf(JwtException.class);
    }

    @Test
    void debeRechazarUnTokenSinLaAudienciaPropia() {
        TokenAcceso token = emitir(propiedades(claves, "auth-api", List.of("scoring-api")), Clock.systemUTC(),
                UUID.randomUUID(), "ANALISTA_CREDITO");

        assertThatThrownBy(() -> decoder().decode(token.valor())).isInstanceOf(JwtException.class);
    }

    @Test
    void debeRechazarUnTokenFirmadoConOtraClave() {
        TokenAcceso token = emitir(propiedades(otrasClaves, "auth-api", AUDIENCIAS), Clock.systemUTC(),
                UUID.randomUUID(), "ADMINISTRADOR_RIESGO");

        assertThatThrownBy(() -> decoder().decode(token.valor())).isInstanceOf(JwtException.class);
    }

    @Test
    void debeRechazarAlgoritmosDistintosDeRs256YTokensSinFirma() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("auth-api").audience(AUDIENCIAS).subject(UUID.randomUUID().toString())
                .claim("role", "ADMINISTRADOR_RIESGO")
                .issueTime(new Date()).expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build();
        SignedJWT hs256 = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        hs256.sign(new MACSigner(new byte[32]));

        assertThatThrownBy(() -> decoder().decode(hs256.serialize())).isInstanceOf(JwtException.class);
        assertThatThrownBy(() -> decoder().decode(new PlainJWT(claims).serialize())).isInstanceOf(JwtException.class);
    }

    @Test
    void sinClavesConfiguradasNoDebeArrancar() {
        JwtProperties sinClaves = new JwtProperties("auth-api", AUDIENCIAS, "auth-api", "x",
                new FileSystemResource(claves.resolve("no-existe.pem")),
                new FileSystemResource(claves.resolve("no-existe.pem")), Duration.ofMinutes(15));

        assertThat(Files.exists(claves.resolve("no-existe.pem"))).isFalse();
        assertThatThrownBy(() -> CONFIG.jwtDecoder(sinClaves)).isInstanceOf(IllegalStateException.class);
    }
}
