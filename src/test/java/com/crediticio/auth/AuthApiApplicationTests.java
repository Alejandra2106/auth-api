package com.crediticio.auth;

import com.crediticio.auth.support.ClavesRsaPrueba;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Path;

/** Arranque completo con H2 (perfil test) y claves generadas en tiempo de ejecución. */
@SpringBootTest
@ActiveProfiles("test")
class AuthApiApplicationTests {

    @TempDir
    static Path claves;

    @DynamicPropertySource
    static void configurarClaves(DynamicPropertyRegistry registro) {
        ClavesRsaPrueba.escribirPem(ClavesRsaPrueba.generar(), claves);
        registro.add("auth.jwt.clave-privada", () -> "file:" + claves.resolve("clave-privada.pem"));
        registro.add("auth.jwt.clave-publica", () -> "file:" + claves.resolve("clave-publica.pem"));
    }

    @Test
    void elContextoDebeArrancar() {
    }
}
