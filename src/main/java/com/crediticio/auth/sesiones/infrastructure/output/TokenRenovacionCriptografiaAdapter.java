package com.crediticio.auth.sesiones.infrastructure.output;

import com.crediticio.auth.sesiones.ports.output.TokenRenovacionCriptografiaPort;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * 256 bits aleatorios en Base64 URL. Como el token ya tiene entropía completa, un SHA-256 sin sal
 * basta para guardarlo protegido y buscarlo por igualdad (a diferencia de una contraseña).
 */
@Component
public class TokenRenovacionCriptografiaAdapter implements TokenRenovacionCriptografiaPort {

    private static final int BYTES_ALEATORIOS = 32;

    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public String generar() {
        byte[] bytes = new byte[BYTES_ALEATORIOS];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @Override
    public String hashear(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 no está disponible", ex);
        }
    }
}
