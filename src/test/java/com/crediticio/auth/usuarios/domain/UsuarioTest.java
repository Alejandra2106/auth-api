package com.crediticio.auth.usuarios.domain;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UsuarioTest {

    private static final Instant AHORA = Instant.parse("2026-10-16T12:00:00Z");
    private static final CorreoElectronico CORREO = CorreoElectronico.de("ana@ejemplo.com");

    @Test
    void unAltaPorApiDebeQuedarHabilitadaYRegistrarSuAutor() {
        UUID autor = UUID.randomUUID();
        Usuario usuario = Usuario.nuevo(UUID.randomUUID(), CORREO, "$2a$hash", Rol.ANALISTA_CREDITO, AHORA, autor);

        assertThat(usuario.isHabilitado()).isTrue();
        assertThat(usuario.getCreadoPor()).isEqualTo(autor);
        assertThat(usuario.getOrigenCreacion()).isEqualTo(OrigenCreacion.API);
        assertThat(usuario.getFechaCreacion()).isEqualTo(AHORA);
    }

    @Test
    void unAltaPorApiDebeExigirAutor() {
        assertThatThrownBy(() -> Usuario.nuevo(UUID.randomUUID(), CORREO, "$2a$hash", Rol.ANALISTA_CREDITO, AHORA, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void elAdministradorInicialNoTieneAutorYSiempreEsAdministrador() {
        Usuario usuario = Usuario.administradorInicial(UUID.randomUUID(), CORREO, "$2a$hash", AHORA);

        assertThat(usuario.getRol()).isEqualTo(Rol.ADMINISTRADOR_RIESGO);
        assertThat(usuario.getCreadoPor()).isNull();
        assertThat(usuario.getOrigenCreacion()).isEqualTo(OrigenCreacion.INICIALIZACION);
    }

    @Test
    void debeRechazarRolNulo() {
        assertThatThrownBy(() -> Usuario.nuevo(UUID.randomUUID(), CORREO, "$2a$hash", null, AHORA, UUID.randomUUID()))
                .isInstanceOf(UsuarioInvalidoException.class)
                .hasMessage("rol es obligatorio");
    }

    @Test
    void reconstruirDebeRechazarUnaInicializacionConAutor() {
        assertThatThrownBy(() -> Usuario.reconstruir(UUID.randomUUID(), CORREO, "$2a$hash", Rol.ADMINISTRADOR_RIESGO,
                true, AHORA, UUID.randomUUID(), OrigenCreacion.INICIALIZACION))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void toStringNoDebeExponerElHash() {
        Usuario usuario = Usuario.nuevo(UUID.randomUUID(), CORREO, "$2a$12$hashSecreto", Rol.ANALISTA_CREDITO, AHORA,
                UUID.randomUUID());

        assertThat(usuario.toString()).doesNotContain("hashSecreto").doesNotContain("ana@ejemplo.com");
    }
}
