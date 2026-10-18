package com.crediticio.auth.sesiones.application;

import com.crediticio.auth.sesiones.domain.CredencialesInvalidasException;
import com.crediticio.auth.sesiones.domain.SesionEmitida;
import com.crediticio.auth.sesiones.domain.SesionInvalidaException;
import com.crediticio.auth.sesiones.domain.TokenAcceso;
import com.crediticio.auth.sesiones.domain.TokenRenovacion;
import com.crediticio.auth.sesiones.ports.output.EmisorTokenAccesoPort;
import com.crediticio.auth.sesiones.ports.output.TokenRenovacionCriptografiaPort;
import com.crediticio.auth.sesiones.ports.output.TokenRenovacionRepositoryPort;
import com.crediticio.auth.sesiones.ports.output.UsuarioSesion;
import com.crediticio.auth.sesiones.ports.output.UsuarioSesionPort;
import com.crediticio.auth.sesiones.ports.output.VerificadorContrasenaPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SesionesServiceTest {

    private static final Instant AHORA = Instant.parse("2026-10-16T12:00:00Z");
    private static final Duration SIETE_DIAS = Duration.ofDays(7);
    private static final UUID ID_USUARIO = UUID.randomUUID();
    private static final String HASH_TOKEN = "b".repeat(64);
    private static final UsuarioSesion ANALISTA = new UsuarioSesion(ID_USUARIO, "$2a$hash", "ANALISTA_CREDITO", true);

    @Mock
    private UsuarioSesionPort usuarioSesionPort;

    @Mock
    private VerificadorContrasenaPort verificadorContrasenaPort;

    @Mock
    private TokenRenovacionRepositoryPort tokenRenovacionRepositoryPort;

    @Mock
    private TokenRenovacionCriptografiaPort criptografiaPort;

    @Mock
    private EmisorTokenAccesoPort emisorTokenAccesoPort;

    private final Clock clock = Clock.fixed(AHORA, ZoneOffset.UTC);
    private EmisionSesion emisionSesion;

    @BeforeEach
    void inicializar() {
        emisionSesion = new EmisionSesion(tokenRenovacionRepositoryPort, criptografiaPort, emisorTokenAccesoPort,
                SIETE_DIAS, clock);
    }

    private void prepararEmision(String rol) {
        when(criptografiaPort.generar()).thenReturn("token-nuevo");
        when(criptografiaPort.hashear("token-nuevo")).thenReturn("c".repeat(64));
        when(emisorTokenAccesoPort.emitir(ID_USUARIO, rol)).thenReturn(new TokenAcceso("jwt", 900));
    }

    @Nested
    class IniciarSesion {

        private IniciarSesionService servicio;

        @BeforeEach
        void inicializar() {
            servicio = new IniciarSesionService(usuarioSesionPort, verificadorContrasenaPort, emisionSesion);
        }

        @Test
        void debeEmitirJwtYGuardarSoloElHashDelTokenDeRenovacion() {
            when(usuarioSesionPort.buscarPorCorreo("ana@ejemplo.com")).thenReturn(Optional.of(ANALISTA));
            when(verificadorContrasenaPort.coincide("contrasena-segura", "$2a$hash")).thenReturn(true);
            prepararEmision("ANALISTA_CREDITO");

            SesionEmitida sesion = servicio.iniciar("ana@ejemplo.com", "contrasena-segura");

            ArgumentCaptor<TokenRenovacion> captor = ArgumentCaptor.forClass(TokenRenovacion.class);
            verify(tokenRenovacionRepositoryPort).guardar(captor.capture());
            assertThat(captor.getValue().getHashToken()).isEqualTo("c".repeat(64)).isNotEqualTo("token-nuevo");
            assertThat(captor.getValue().getExpiraEn()).isEqualTo(AHORA.plus(SIETE_DIAS));
            assertThat(sesion.tokenRenovacion()).isEqualTo("token-nuevo");
            assertThat(sesion.tokenAcceso().valor()).isEqualTo("jwt");
            assertThat(sesion.toString()).doesNotContain("token-nuevo").doesNotContain("jwt");
        }

        @Test
        void contrasenaIncorrectaDebeFallarConElErrorGenerico() {
            when(usuarioSesionPort.buscarPorCorreo("ana@ejemplo.com")).thenReturn(Optional.of(ANALISTA));
            when(verificadorContrasenaPort.coincide("incorrecta", "$2a$hash")).thenReturn(false);

            assertThatThrownBy(() -> servicio.iniciar("ana@ejemplo.com", "incorrecta"))
                    .isInstanceOf(CredencialesInvalidasException.class);
            verify(tokenRenovacionRepositoryPort, never()).guardar(any());
        }

        @Test
        void usuarioInexistenteDebeVerificarContraUnHashFicticioYFallarIgual() {
            when(usuarioSesionPort.buscarPorCorreo("nadie@ejemplo.com")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> servicio.iniciar("nadie@ejemplo.com", "contrasena-segura"))
                    .isInstanceOf(CredencialesInvalidasException.class);
            verify(verificadorContrasenaPort).verificarSinUsuario("contrasena-segura");
        }

        @Test
        void cuentaDeshabilitadaDebeFallarIgualAunqueLaContrasenaSeaCorrecta() {
            UsuarioSesion deshabilitado = new UsuarioSesion(ID_USUARIO, "$2a$hash", "ANALISTA_CREDITO", false);
            when(usuarioSesionPort.buscarPorCorreo("ana@ejemplo.com")).thenReturn(Optional.of(deshabilitado));
            when(verificadorContrasenaPort.coincide("contrasena-segura", "$2a$hash")).thenReturn(true);

            assertThatThrownBy(() -> servicio.iniciar("ana@ejemplo.com", "contrasena-segura"))
                    .isInstanceOf(CredencialesInvalidasException.class);
            verify(tokenRenovacionRepositoryPort, never()).guardar(any());
        }
    }

    @Nested
    class RenovarSesion {

        private RenovarSesionService servicio;
        private final UUID familia = UUID.randomUUID();

        @BeforeEach
        void inicializar() {
            servicio = new RenovarSesionService(tokenRenovacionRepositoryPort, criptografiaPort, usuarioSesionPort,
                    emisionSesion, clock);
            when(criptografiaPort.hashear("token-actual")).thenReturn(HASH_TOKEN);
        }

        private TokenRenovacion token(Instant usadoEn, Instant revocadoEn, Instant expiraEn) {
            return TokenRenovacion.reconstruir(UUID.randomUUID(), ID_USUARIO, familia, HASH_TOKEN,
                    AHORA.minus(Duration.ofDays(1)), expiraEn, usadoEn, revocadoEn);
        }

        @Test
        void debeRotarEnLaMismaFamiliaYEmitirElRolActualDelUsuario() {
            TokenRenovacion vigente = token(null, null, AHORA.plus(Duration.ofDays(1)));
            when(tokenRenovacionRepositoryPort.buscarPorHashParaActualizar(HASH_TOKEN)).thenReturn(Optional.of(vigente));
            UsuarioSesion ahoraAdministrador = new UsuarioSesion(ID_USUARIO, "$2a$hash", "ADMINISTRADOR_RIESGO", true);
            when(usuarioSesionPort.buscarPorId(ID_USUARIO)).thenReturn(Optional.of(ahoraAdministrador));
            when(tokenRenovacionRepositoryPort.marcarUsado(vigente.getIdToken(), AHORA)).thenReturn(true);
            prepararEmision("ADMINISTRADOR_RIESGO");

            SesionEmitida sesion = servicio.renovar("token-actual");

            ArgumentCaptor<TokenRenovacion> captor = ArgumentCaptor.forClass(TokenRenovacion.class);
            verify(tokenRenovacionRepositoryPort).guardar(captor.capture());
            assertThat(captor.getValue().getFamilia()).isEqualTo(familia);
            assertThat(sesion.tokenRenovacion()).isEqualTo("token-nuevo");
            verify(tokenRenovacionRepositoryPort, never()).revocarFamilia(any(), any());
        }

        @Test
        void reutilizarUnTokenRotadoDebeRevocarLaFamiliaYFallar() {
            TokenRenovacion usado = token(AHORA.minusSeconds(30), null, AHORA.plus(Duration.ofDays(1)));
            when(tokenRenovacionRepositoryPort.buscarPorHashParaActualizar(HASH_TOKEN)).thenReturn(Optional.of(usado));

            assertThatThrownBy(() -> servicio.renovar("token-actual")).isInstanceOf(SesionInvalidaException.class);

            verify(tokenRenovacionRepositoryPort).revocarFamilia(familia, AHORA);
            verify(tokenRenovacionRepositoryPort, never()).guardar(any());
        }

        @Test
        void unTokenRevocadoOExpiradoDebeFallarSinEmitirNada() {
            TokenRenovacion revocado = token(null, AHORA.minusSeconds(5), AHORA.plus(Duration.ofDays(1)));
            when(tokenRenovacionRepositoryPort.buscarPorHashParaActualizar(HASH_TOKEN)).thenReturn(Optional.of(revocado));
            assertThatThrownBy(() -> servicio.renovar("token-actual")).isInstanceOf(SesionInvalidaException.class);

            TokenRenovacion expirado = token(null, null, AHORA);
            when(tokenRenovacionRepositoryPort.buscarPorHashParaActualizar(HASH_TOKEN)).thenReturn(Optional.of(expirado));
            assertThatThrownBy(() -> servicio.renovar("token-actual")).isInstanceOf(SesionInvalidaException.class);

            verify(tokenRenovacionRepositoryPort, never()).guardar(any());
            verify(tokenRenovacionRepositoryPort, never()).marcarUsado(any(), any());
        }

        @Test
        void unTokenDesconocidoDebeFallar() {
            when(tokenRenovacionRepositoryPort.buscarPorHashParaActualizar(HASH_TOKEN)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> servicio.renovar("token-actual")).isInstanceOf(SesionInvalidaException.class);
        }

        @Test
        void unUsuarioDeshabilitadoNoDebeRenovarYDebeRevocarseLaFamilia() {
            TokenRenovacion vigente = token(null, null, AHORA.plus(Duration.ofDays(1)));
            when(tokenRenovacionRepositoryPort.buscarPorHashParaActualizar(HASH_TOKEN)).thenReturn(Optional.of(vigente));
            when(usuarioSesionPort.buscarPorId(ID_USUARIO))
                    .thenReturn(Optional.of(new UsuarioSesion(ID_USUARIO, "$2a$hash", "ANALISTA_CREDITO", false)));

            assertThatThrownBy(() -> servicio.renovar("token-actual")).isInstanceOf(SesionInvalidaException.class);

            verify(tokenRenovacionRepositoryPort).revocarFamilia(familia, AHORA);
            verify(tokenRenovacionRepositoryPort, never()).marcarUsado(any(), any());
        }

        @Test
        void siOtraTransaccionYaUsoElTokenNoDebeEmitir() {
            TokenRenovacion vigente = token(null, null, AHORA.plus(Duration.ofDays(1)));
            when(tokenRenovacionRepositoryPort.buscarPorHashParaActualizar(HASH_TOKEN)).thenReturn(Optional.of(vigente));
            when(usuarioSesionPort.buscarPorId(ID_USUARIO)).thenReturn(Optional.of(ANALISTA));
            when(tokenRenovacionRepositoryPort.marcarUsado(vigente.getIdToken(), AHORA)).thenReturn(false);

            assertThatThrownBy(() -> servicio.renovar("token-actual")).isInstanceOf(SesionInvalidaException.class);
            verify(tokenRenovacionRepositoryPort, never()).guardar(any());
        }
    }

    @Nested
    class CerrarSesion {

        @Test
        void debeRevocarLaFamiliaDelTokenPresentado() {
            UUID familia = UUID.randomUUID();
            when(criptografiaPort.hashear("token-actual")).thenReturn(HASH_TOKEN);
            when(tokenRenovacionRepositoryPort.buscarPorHashParaActualizar(HASH_TOKEN)).thenReturn(Optional.of(
                    TokenRenovacion.reconstruir(UUID.randomUUID(), ID_USUARIO, familia, HASH_TOKEN, AHORA,
                            AHORA.plus(SIETE_DIAS), null, null)));

            new CerrarSesionService(tokenRenovacionRepositoryPort, criptografiaPort, clock).cerrar("token-actual");

            verify(tokenRenovacionRepositoryPort).revocarFamilia(familia, AHORA);
        }

        @Test
        void unTokenAusenteODesconocidoNoDebeFallar() {
            when(criptografiaPort.hashear(anyString())).thenReturn(HASH_TOKEN);
            when(tokenRenovacionRepositoryPort.buscarPorHashParaActualizar(HASH_TOKEN)).thenReturn(Optional.empty());
            CerrarSesionService servicio = new CerrarSesionService(tokenRenovacionRepositoryPort, criptografiaPort,
                    clock);

            servicio.cerrar(null);
            servicio.cerrar("desconocido");

            verify(tokenRenovacionRepositoryPort, never()).revocarFamilia(any(), any());
        }
    }
}
