package com.crediticio.auth.sesiones.infrastructure.output;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class TokenRenovacionCriptografiaAdapterTest {

    private final TokenRenovacionCriptografiaAdapter adapter = new TokenRenovacionCriptografiaAdapter();

    @Test
    void debeGenerarTokensDe256BitsAptosParaCookieYDistintos() {
        Set<String> generados = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            String token = adapter.generar();
            assertThat(token).matches("[A-Za-z0-9_-]{43}");
            generados.add(token);
        }
        assertThat(generados).hasSize(100);
    }

    @Test
    void elHashDebeSerSha256HexadecimalDeterministaYDistintoDelToken() {
        String token = adapter.generar();

        String hash = adapter.hashear(token);

        assertThat(hash).matches("[0-9a-f]{64}").isEqualTo(adapter.hashear(token)).isNotEqualTo(token);
        assertThat(adapter.hashear("abc"))
                .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
