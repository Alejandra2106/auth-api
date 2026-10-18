package com.crediticio.auth.usuarios.application;

import com.crediticio.auth.usuarios.domain.CorreoElectronico;
import com.crediticio.auth.usuarios.domain.OrigenCreacion;
import com.crediticio.auth.usuarios.domain.Rol;
import com.crediticio.auth.usuarios.domain.Usuario;
import com.crediticio.auth.usuarios.domain.UsuarioInvalidoException;
import com.crediticio.auth.usuarios.ports.output.HashContrasenaPort;
import com.crediticio.auth.usuarios.ports.output.RevocarSesionesUsuarioPort;
import com.crediticio.auth.usuarios.ports.output.UsuarioRepositoryPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RestablecerContrasenaAdministradorServiceTest {

    private static final UUID ID_ADMIN = UUID.randomUUID();
    private static final Instant FECHA_CREACION = Instant.parse("2026-10-16T12:00:00Z");

    @Mock
    private UsuarioRepositoryPort usuarioRepositoryPort;

    @Mock
    private HashContrasenaPort hashContrasenaPort;

    @Mock
    private RevocarSesionesUsuarioPort revocarSesionesUsuarioPort;

    private RestablecerContrasenaAdministradorService servicio;

    @BeforeEach
    void inicializar() {
        servicio = new RestablecerContrasenaAdministradorService(usuarioRepositoryPort, hashContrasenaPort,
                revocarSesionesUsuarioPort, Clock.fixed(Instant.parse("2026-10-17T12:00:00Z"), ZoneOffset.UTC));
    }

    @Test
    void actualizaSoloElHashDelAdministradorIndicado() {
        Usuario existente = administrador();
        when(usuarioRepositoryPort.buscarPorCorreo(CorreoElectronico.de("admin@ejemplo.com")))
                .thenReturn(Optional.of(existente));
        when(hashContrasenaPort.hashear("nueva-contrasena-segura"))
                .thenReturn("{pbkdf2}hash-nuevo");
        when(usuarioRepositoryPort.guardar(any(Usuario.class))).thenAnswer(invocacion -> invocacion.getArgument(0));

        servicio.restablecer("ADMIN@ejemplo.com", "nueva-contrasena-segura");

        ArgumentCaptor<Usuario> captor = ArgumentCaptor.forClass(Usuario.class);
        verify(usuarioRepositoryPort).guardar(captor.capture());
        Usuario actualizado = captor.getValue();
        assertThat(actualizado.getIdUsuario()).isEqualTo(ID_ADMIN);
        assertThat(actualizado.getCorreo()).isEqualTo(existente.getCorreo());
        assertThat(actualizado.getHashContrasena()).isEqualTo("{pbkdf2}hash-nuevo");
        assertThat(actualizado.getRol()).isEqualTo(Rol.ADMINISTRADOR_RIESGO);
        assertThat(actualizado.isHabilitado()).isTrue();
        assertThat(actualizado.getFechaCreacion()).isEqualTo(FECHA_CREACION);
        assertThat(actualizado.getOrigenCreacion()).isEqualTo(OrigenCreacion.INICIALIZACION);
        verify(revocarSesionesUsuarioPort).revocarSesiones(ID_ADMIN, Instant.parse("2026-10-17T12:00:00Z"));
    }

    @Test
    void rechazaUnaCuentaQueNoEsAdministradoraSinCambiarla() {
        Usuario analista = Usuario.nuevo(UUID.randomUUID(), CorreoElectronico.de("analista@ejemplo.com"),
                "{pbkdf2}hash-anterior", Rol.ANALISTA_CREDITO, FECHA_CREACION, UUID.randomUUID());
        when(usuarioRepositoryPort.buscarPorCorreo(CorreoElectronico.de("analista@ejemplo.com")))
                .thenReturn(Optional.of(analista));

        assertThatThrownBy(() -> servicio.restablecer("analista@ejemplo.com", "nueva-contrasena-segura"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("El correo indicado no pertenece a un administrador");

        verify(usuarioRepositoryPort, never()).guardar(any());
        verifyNoInteractions(hashContrasenaPort, revocarSesionesUsuarioPort);
    }

    @Test
    void rechazaContrasenaQueNoCumpleLaPoliticaSinModificarLaCuenta() {
        assertThatThrownBy(() -> servicio.restablecer("admin@ejemplo.com", "corta"))
                .isInstanceOf(UsuarioInvalidoException.class);

        verifyNoInteractions(usuarioRepositoryPort, hashContrasenaPort, revocarSesionesUsuarioPort);
    }

    private static Usuario administrador() {
        return Usuario.administradorInicial(ID_ADMIN, CorreoElectronico.de("admin@ejemplo.com"),
                "{pbkdf2}hash-anterior", FECHA_CREACION);
    }
}
