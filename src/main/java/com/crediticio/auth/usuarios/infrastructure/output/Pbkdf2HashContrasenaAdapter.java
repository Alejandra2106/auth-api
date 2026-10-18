package com.crediticio.auth.usuarios.infrastructure.output;

import com.crediticio.auth.usuarios.ports.output.HashContrasenaPort;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;

/**
 * HU08 CA05: PBKDF2-HMAC-SHA256 (hash adaptativo) con sal aleatoria de 16 bytes por contraseña y
 * hash de 256 bits. A diferencia de BCrypt, no tiene un límite práctico de longitud, por lo que no
 * se trunca ni se impone un máximo que HU08 no establece. Las iteraciones se calibran por ambiente.
 * El hash se guarda con el prefijo del algoritmo ({pbkdf2}), para que un cambio futuro de
 * algoritmo pueda convivir con los hashes existentes.
 */
@Component
public class Pbkdf2HashContrasenaAdapter implements HashContrasenaPort {

    static final String ID_ALGORITMO = "pbkdf2";
    private static final int BYTES_SAL = 16;

    private final PasswordEncoder encoder;
    private final String hashFicticio;

    public Pbkdf2HashContrasenaAdapter(@Value("${auth.pbkdf2.iteraciones:600000}") int iteraciones) {
        if (iteraciones < 1) {
            throw new IllegalArgumentException("auth.pbkdf2.iteraciones debe ser positivo");
        }
        Pbkdf2PasswordEncoder pbkdf2 = new Pbkdf2PasswordEncoder("", BYTES_SAL, iteraciones,
                Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256);
        this.encoder = new DelegatingPasswordEncoder(ID_ALGORITMO, Map.of(ID_ALGORITMO, pbkdf2));
        byte[] aleatorio = new byte[24];
        new SecureRandom().nextBytes(aleatorio);
        this.hashFicticio = encoder.encode(HexFormat.of().formatHex(aleatorio));
    }

    @Override
    public String hashear(String contrasena) {
        return encoder.encode(contrasena);
    }

    @Override
    public boolean coincide(String contrasena, String hash) {
        if (contrasena == null || hash == null) {
            return false;
        }
        try {
            return encoder.matches(contrasena, hash);
        } catch (IllegalArgumentException ex) {
            // hash sin prefijo de algoritmo conocido o con formato inválido: no coincide
            return false;
        }
    }

    @Override
    public String hashFicticio() {
        return hashFicticio;
    }
}
