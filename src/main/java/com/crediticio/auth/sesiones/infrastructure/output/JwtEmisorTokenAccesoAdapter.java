package com.crediticio.auth.sesiones.infrastructure.output;

import com.crediticio.auth.config.JwtProperties;
import com.crediticio.auth.sesiones.domain.TokenAcceso;
import com.crediticio.auth.sesiones.ports.output.EmisorTokenAccesoPort;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * HU09 CA03–CA04. Contrato común de las tres API: RS256 con kid; claims iss, aud, sub (UUID del
 * usuario), role (un único rol), iat, exp (15 minutos) y jti. No incluye correo ni otros datos personales.
 */
@Component
public class JwtEmisorTokenAccesoAdapter implements EmisorTokenAccesoPort {

    public static final String CLAIM_ROL = "role";

    private final JwtEncoder jwtEncoder;
    private final JwtProperties jwtProperties;
    private final Clock clock;

    public JwtEmisorTokenAccesoAdapter(JwtEncoder jwtEncoder, JwtProperties jwtProperties, Clock clock) {
        this.jwtEncoder = jwtEncoder;
        this.jwtProperties = jwtProperties;
        this.clock = clock;
    }

    @Override
    public TokenAcceso emitir(UUID idUsuario, String rol) {
        Instant ahora = Instant.now(clock);
        JwsHeader cabecera = JwsHeader.with(SignatureAlgorithm.RS256).keyId(jwtProperties.idClave()).build();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(jwtProperties.emisor())
                .audience(jwtProperties.audiencias())
                .subject(idUsuario.toString())
                .claim(CLAIM_ROL, rol)
                .issuedAt(ahora)
                .expiresAt(ahora.plus(jwtProperties.duracionAcceso()))
                .id(UUID.randomUUID().toString())
                .build();
        String valor = jwtEncoder.encode(JwtEncoderParameters.from(cabecera, claims)).getTokenValue();
        return new TokenAcceso(valor, jwtProperties.duracionAcceso().toSeconds());
    }
}
