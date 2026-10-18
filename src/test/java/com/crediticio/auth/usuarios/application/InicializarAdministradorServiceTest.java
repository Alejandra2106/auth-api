package com.crediticio.auth.usuarios.application;

import com.crediticio.auth.usuarios.domain.AdministradorYaInicializadoException;
import com.crediticio.auth.usuarios.domain.OrigenCreacion;
import com.crediticio.auth.usuarios.domain.Rol;
import com.crediticio.auth.usuarios.domain.Usuario;
import com.crediticio.auth.usuarios.domain.UsuarioInvalidoException;
import com.crediticio.auth.usuarios.ports.output.HashContrasenaPort;
import com.crediticio.auth.usuarios.ports.output.UsuarioRepositoryPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class InicializarAdministradorServiceTest {

    private static final Instant AHORA = Instant.parse("2026-10-16T12:00:00Z");

    @Mock
    private UsuarioRepositoryPort usuarioRepositoryPort;

    @Mock
    private HashContrasenaPort hashContrasenaPort;

    private InicializarAdministradorService servicio;

    @BeforeEach
    void inicializar() {
        servicio = new InicializarAdministradorService(usuarioRepositoryPort, hashContrasenaPort,
                Clock.fixed(AHORA, ZoneOffset.UTC));
    }

    @Test
    void debeBloquearAntesDeComprobarYCrearElAdministradorSinAutor() {
        when(usuarioRepositoryPort.existeAdministrador()).thenReturn(false);
        when(usuarioRepositoryPort.existePorCorreo(any())).thenReturn(false);
        when(hashContrasenaPort.hashear("contrasena-inicial")).thenReturn("$2a$12$hash");
        when(usuarioRepositoryPort.guardar(any(Usuario.class))).thenAnswer(invocacion -> invocacion.getArgument(0));

        servicio.inicializar("Admin@Ejemplo.com", "contrasena-inicial");

        InOrder orden = inOrder(usuarioRepositoryPort);
        orden.verify(usuarioRepositoryPort).bloquearInicializacionAdministrador();
        orden.verify(usuarioRepositoryPort).existeAdministrador();
        ArgumentCaptor<Usuario> captor = ArgumentCaptor.forClass(Usuario.class);
        orden.verify(usuarioRepositoryPort).guardar(captor.capture());
        assertThat(captor.getValue().getRol()).isEqualTo(Rol.ADMINISTRADOR_RIESGO);
        assertThat(captor.getValue().getCreadoPor()).isNull();
        assertThat(captor.getValue().getOrigenCreacion()).isEqualTo(OrigenCreacion.INICIALIZACION);
        assertThat(captor.getValue().getCorreo().valor()).isEqualTo("admin@ejemplo.com");
    }

    @Test
    void siYaExisteUnAdministradorNoDebeCrearOtro() {
        when(usuarioRepositoryPort.existeAdministrador()).thenReturn(true);

        assertThatThrownBy(() -> servicio.inicializar("admin@ejemplo.com", "contrasena-inicial"))
                .isInstanceOf(AdministradorYaInicializadoException.class);

        verify(usuarioRepositoryPort, never()).guardar(any());
        verifyNoInteractions(hashContrasenaPort);
    }

    @Test
    void debeAplicarLaPoliticaDeContrasena() {
        when(usuarioRepositoryPort.existeAdministrador()).thenReturn(false);

        assertThatThrownBy(() -> servicio.inicializar("admin@ejemplo.com", "corta"))
                .isInstanceOf(UsuarioInvalidoException.class);

        verify(usuarioRepositoryPort, never()).guardar(any());
    }
}
