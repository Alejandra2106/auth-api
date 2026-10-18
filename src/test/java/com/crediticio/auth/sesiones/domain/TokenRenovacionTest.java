package com.crediticio.auth.sesiones.domain;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenRenovacionTest {

    private static final Instant AHORA = Instant.parse("2026-10-16T12:00:00Z");
    private static final String HASH = "a".repeat(64);

    @Test
    void unTokenRecienEmitidoDebeEstarVigenteHastaJustoAntesDeExpirar() {
        TokenRenovacion token = TokenRenovacion.emitir(UUID.randomUUID(), UUID.randomUUID(), HASH, AHORA,
                Duration.ofDays(7));

        assertThat(token.getExpiraEn()).isEqualTo(AHORA.plus(Duration.ofDays(7)));
        assertThat(token.estado(AHORA)).isEqualTo(EstadoTokenRenovacion.VIGENTE);
        assertThat(token.estado(token.getExpiraEn().minusNanos(1))).isEqualTo(EstadoTokenRenovacion.VIGENTE);
        assertThat(token.estado(token.getExpiraEn())).isEqualTo(EstadoTokenRenovacion.EXPIRADO);
    }

    @Test
    void debeRechazarUnaVigenciaSuperiorASieteDias() {
        assertThatThrownBy(() -> TokenRenovacion.emitir(UUID.randomUUID(), UUID.randomUUID(), HASH, AHORA,
                Duration.ofDays(7).plusSeconds(1)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void debeRechazarUnaVigenciaNoPositiva() {
        assertThatThrownBy(() -> TokenRenovacion.emitir(UUID.randomUUID(), UUID.randomUUID(), HASH, AHORA,
                Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void laRevocacionDebePrevalecerSobreElUsoYElUsoSobreLaExpiracion() {
        UUID id = UUID.randomUUID();
        Instant expira = AHORA.plus(Duration.ofDays(1));
        TokenRenovacion usado = TokenRenovacion.reconstruir(id, UUID.randomUUID(), UUID.randomUUID(), HASH, AHORA,
                expira, AHORA.plusSeconds(5), null);
        TokenRenovacion usadoYRevocado = TokenRenovacion.reconstruir(id, UUID.randomUUID(), UUID.randomUUID(), HASH,
                AHORA, expira, AHORA.plusSeconds(5), AHORA.plusSeconds(10));

        assertThat(usado.estado(expira.plusSeconds(1))).isEqualTo(EstadoTokenRenovacion.USADO);
        assertThat(usadoYRevocado.estado(AHORA)).isEqualTo(EstadoTokenRenovacion.REVOCADO);
    }

    @Test
    void toStringNoDebeExponerElHash() {
        TokenRenovacion token = TokenRenovacion.emitir(UUID.randomUUID(), UUID.randomUUID(), HASH, AHORA,
                Duration.ofDays(1));

        assertThat(token.toString()).doesNotContain(HASH);
    }
}
