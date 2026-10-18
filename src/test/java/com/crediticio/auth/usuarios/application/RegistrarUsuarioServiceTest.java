package com.crediticio.auth.usuarios.application;

import com.crediticio.auth.usuarios.application.dto.RegistrarUsuarioRequest;
import com.crediticio.auth.usuarios.application.dto.UsuarioResponse;
import com.crediticio.auth.usuarios.domain.ActorRequeridoException;
import com.crediticio.auth.usuarios.domain.CorreoDuplicadoException;
import com.crediticio.auth.usuarios.domain.CorreoElectronico;
import com.crediticio.auth.usuarios.domain.OrigenCreacion;
import com.crediticio.auth.usuarios.domain.Rol;
import com.crediticio.auth.usuarios.domain.Usuario;
import com.crediticio.auth.usuarios.domain.UsuarioInvalidoException;
import com.crediticio.auth.usuarios.ports.output.ActorActualPort;
import com.crediticio.auth.usuarios.ports.output.HashContrasenaPort;
import com.crediticio.auth.usuarios.ports.output.UsuarioRepositoryPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
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
class RegistrarUsuarioServiceTest {

    private static final Instant AHORA = Instant.parse("2026-10-16T12:00:00Z");
    private static final UUID ADMINISTRADOR = UUID.randomUUID();

    @Mock
    private UsuarioRepositoryPort usuarioRepositoryPort;

    @Mock
    private HashContrasenaPort hashContrasenaPort;

    @Mock
    private ActorActualPort actorActualPort;

    private RegistrarUsuarioService servicio;

    @BeforeEach
    void inicializar() {
        servicio = new RegistrarUsuarioService(usuarioRepositoryPort, hashContrasenaPort, actorActualPort,
                new UsuarioMapper(), Clock.fixed(AHORA, ZoneOffset.UTC));
    }

    @Test
    void debeRegistrarConCorreoNormalizadoHashYAutorSinExponerLaContrasena() {
        when(actorActualPort.idActorAutenticado()).thenReturn(Optional.of(ADMINISTRADOR));
        when(usuarioRepositoryPort.existePorCorreo(CorreoElectronico.de("ana@ejemplo.com"))).thenReturn(false);
        when(hashContrasenaPort.hashear("contrasena-segura")).thenReturn("$2a$12$hash");
        when(usuarioRepositoryPort.guardar(any(Usuario.class))).thenAnswer(invocacion -> invocacion.getArgument(0));

        UsuarioResponse respuesta = servicio.registrar(
                new RegistrarUsuarioRequest("  Ana@Ejemplo.com ", "contrasena-segura", Rol.ANALISTA_CREDITO));

        ArgumentCaptor<Usuario> captor = ArgumentCaptor.forClass(Usuario.class);
        verify(usuarioRepositoryPort).guardar(captor.capture());
        Usuario guardado = captor.getValue();
        assertThat(guardado.getCorreo().valor()).isEqualTo("ana@ejemplo.com");
        assertThat(guardado.getHashContrasena()).isEqualTo("$2a$12$hash");
        assertThat(guardado.getRol()).isEqualTo(Rol.ANALISTA_CREDITO);
        assertThat(guardado.getCreadoPor()).isEqualTo(ADMINISTRADOR);
        assertThat(guardado.getOrigenCreacion()).isEqualTo(OrigenCreacion.API);
        assertThat(guardado.getFechaCreacion()).isEqualTo(AHORA);
        assertThat(respuesta.correo()).isEqualTo("ana@ejemplo.com");
        assertThat(respuesta.rol()).isEqualTo(Rol.ANALISTA_CREDITO);
        assertThat(respuesta.toString()).doesNotContain("contrasena-segura").doesNotContain("$2a$12$hash");
    }

    @Test
    void debeRechazarUnCorreoYaRegistradoSinDistinguirMayusculas() {
        when(actorActualPort.idActorAutenticado()).thenReturn(Optional.of(ADMINISTRADOR));
        when(usuarioRepositoryPort.existePorCorreo(CorreoElectronico.de("ana@ejemplo.com"))).thenReturn(true);

        assertThatThrownBy(() -> servicio.registrar(
                new RegistrarUsuarioRequest("ANA@EJEMPLO.COM", "contrasena-segura", Rol.ANALISTA_CREDITO)))
                .isInstanceOf(CorreoDuplicadoException.class);

        verify(usuarioRepositoryPort, never()).guardar(any());
        verifyNoInteractions(hashContrasenaPort);
    }

    @Test
    void debePropagarElDuplicadoDetectadoPorLaBaseBajoConcurrencia() {
        when(actorActualPort.idActorAutenticado()).thenReturn(Optional.of(ADMINISTRADOR));
        when(usuarioRepositoryPort.existePorCorreo(any())).thenReturn(false);
        when(hashContrasenaPort.hashear(any())).thenReturn("$2a$12$hash");
        when(usuarioRepositoryPort.guardar(any())).thenThrow(new CorreoDuplicadoException());

        assertThatThrownBy(() -> servicio.registrar(
                new RegistrarUsuarioRequest("ana@ejemplo.com", "contrasena-segura", Rol.ANALISTA_CREDITO)))
                .isInstanceOf(CorreoDuplicadoException.class);
    }

    @Test
    void debeRechazarUnaContrasenaCortaSinHashearNiPersistir() {
        when(actorActualPort.idActorAutenticado()).thenReturn(Optional.of(ADMINISTRADOR));

        assertThatThrownBy(() -> servicio.registrar(
                new RegistrarUsuarioRequest("ana@ejemplo.com", "corta", Rol.ANALISTA_CREDITO)))
                .isInstanceOf(UsuarioInvalidoException.class);

        verifyNoInteractions(hashContrasenaPort);
        verify(usuarioRepositoryPort, never()).guardar(any());
    }

    @Test
    void sinActorAutenticadoNoDebeRegistrarNada() {
        when(actorActualPort.idActorAutenticado()).thenReturn(Optional.empty());

        assertThatThrownBy(() -> servicio.registrar(
                new RegistrarUsuarioRequest("ana@ejemplo.com", "contrasena-segura", Rol.ADMINISTRADOR_RIESGO)))
                .isInstanceOf(ActorRequeridoException.class);

        verifyNoInteractions(usuarioRepositoryPort, hashContrasenaPort);
    }

    @Test
    void elToStringDeLaSolicitudNoDebeExponerLaContrasena() {
        assertThat(new RegistrarUsuarioRequest("ana@ejemplo.com", "contrasena-segura", Rol.ANALISTA_CREDITO)
                .toString()).doesNotContain("contrasena-segura");
    }
}
