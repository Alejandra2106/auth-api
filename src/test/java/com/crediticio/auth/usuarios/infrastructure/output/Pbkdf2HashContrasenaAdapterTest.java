package com.crediticio.auth.usuarios.infrastructure.output;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class Pbkdf2HashContrasenaAdapterTest {

    // pocas iteraciones solo para que la prueba sea rápida; el algoritmo es el mismo
    private final Pbkdf2HashContrasenaAdapter adapter = new Pbkdf2HashContrasenaAdapter(1_000);

    @Test
    void debeGuardarPbkdf2ConPrefijoSalAleatoriaYNuncaElTextoPlano() {
        String hash1 = adapter.hashear("contrasena-segura");
        String hash2 = adapter.hashear("contrasena-segura");

        // {pbkdf2} + hex de 16 bytes de sal y 32 bytes de hash (PBKDF2-HMAC-SHA256)
        assertThat(hash1).matches("\\{pbkdf2}[0-9a-f]{96}").doesNotContain("contrasena-segura");
        assertThat(hash1).isNotEqualTo(hash2);
        assertThat(adapter.coincide("contrasena-segura", hash1)).isTrue();
        assertThat(adapter.coincide("contrasena-segura", hash2)).isTrue();
        assertThat(adapter.coincide("contrasena-segurA", hash1)).isFalse();
    }

    @Test
    void debeVerificarContrasenasLargasSinTruncarlas() {
        String larga = "x".repeat(300);
        String hash = adapter.hashear(larga);

        assertThat(adapter.coincide(larga, hash)).isTrue();
        // difieren solo después del byte 72: con BCrypt coincidirían; con PBKDF2 no
        assertThat(adapter.coincide("x".repeat(299) + "y", hash)).isFalse();
    }

    @Test
    void debeVerificarCaracteresNoAscii() {
        String hash = adapter.hashear("contraseña-ñandú-😀");

        assertThat(adapter.coincide("contraseña-ñandú-😀", hash)).isTrue();
        assertThat(adapter.coincide("contrasena-nandu-😀", hash)).isFalse();
    }

    @Test
    void entradasInesperadasNoDebenLanzarSinoNoCoincidir() {
        String hash = adapter.hashear("contrasena-segura");

        assertThat(adapter.coincide(null, hash)).isFalse();
        assertThat(adapter.coincide("contrasena-segura", null)).isFalse();
        assertThat(adapter.coincide("contrasena-segura", "no-es-un-hash")).isFalse();
        assertThat(adapter.coincide("contrasena-segura", "{bcrypt}$2a$10$abc")).isFalse();
    }

    @Test
    void elHashFicticioDebeSerUnPbkdf2ValidoQueNoCoincideConContrasenasComunes() {
        assertThat(adapter.hashFicticio()).startsWith("{pbkdf2}");
        assertThat(adapter.coincide("contrasena-segura", adapter.hashFicticio())).isFalse();
    }

    @Test
    void debeRechazarIteracionesNoPositivas() {
        assertThatThrownBy(() -> new Pbkdf2HashContrasenaAdapter(0)).isInstanceOf(IllegalArgumentException.class);
    }
}
