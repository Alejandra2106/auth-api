package com.crediticio.auth.sesiones.application;

import com.crediticio.auth.sesiones.domain.EstadoTokenRenovacion;
import com.crediticio.auth.sesiones.domain.SesionEmitida;
import com.crediticio.auth.sesiones.domain.SesionInvalidaException;
import com.crediticio.auth.sesiones.domain.TokenRenovacion;
import com.crediticio.auth.sesiones.ports.input.RenovarSesionUseCase;
import com.crediticio.auth.sesiones.ports.output.TokenRenovacionCriptografiaPort;
import com.crediticio.auth.sesiones.ports.output.TokenRenovacionRepositoryPort;
import com.crediticio.auth.sesiones.ports.output.UsuarioSesion;
import com.crediticio.auth.sesiones.ports.output.UsuarioSesionPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;

/**
 * HU09 CA06–CA10 y CA12, y HU10 CA10. Toda la rotación ocurre en una transacción con la fila del
 * token bloqueada, por lo que dos renovaciones con el mismo token se serializan: la segunda lo
 * encuentra usado y se trata como reutilización. Las revocaciones se confirman aunque la operación
 * termine en SesionInvalidaException (noRollbackFor). El rol del nuevo JWT se lee de la base, de modo
 * que un cambio de rol o una deshabilitación se reflejan en la siguiente renovación.
 */
@Service
public class RenovarSesionService implements RenovarSesionUseCase {

    private static final Logger log = LoggerFactory.getLogger(RenovarSesionService.class);

    private final TokenRenovacionRepositoryPort tokenRenovacionRepositoryPort;
    private final TokenRenovacionCriptografiaPort criptografiaPort;
    private final UsuarioSesionPort usuarioSesionPort;
    private final EmisionSesion emisionSesion;
    private final Clock clock;

    public RenovarSesionService(TokenRenovacionRepositoryPort tokenRenovacionRepositoryPort,
            TokenRenovacionCriptografiaPort criptografiaPort, UsuarioSesionPort usuarioSesionPort,
            EmisionSesion emisionSesion, Clock clock) {
        this.tokenRenovacionRepositoryPort = tokenRenovacionRepositoryPort;
        this.criptografiaPort = criptografiaPort;
        this.usuarioSesionPort = usuarioSesionPort;
        this.emisionSesion = emisionSesion;
        this.clock = clock;
    }

    @Override
    @Transactional(noRollbackFor = SesionInvalidaException.class)
    public SesionEmitida renovar(String tokenRenovacion) {
        if (tokenRenovacion == null || tokenRenovacion.isBlank()) {
            throw new SesionInvalidaException();
        }
        TokenRenovacion token = tokenRenovacionRepositoryPort
                .buscarPorHashParaActualizar(criptografiaPort.hashear(tokenRenovacion))
                .orElseThrow(SesionInvalidaException::new);
        Instant ahora = Instant.now(clock);
        EstadoTokenRenovacion estado = token.estado(ahora);
        if (estado == EstadoTokenRenovacion.USADO) {
            tokenRenovacionRepositoryPort.revocarFamilia(token.getFamilia(), ahora);
            log.warn("Reutilización de un token de renovación rotado; se revoca la familia {}", token.getFamilia());
            throw new SesionInvalidaException();
        }
        if (estado != EstadoTokenRenovacion.VIGENTE) {
            throw new SesionInvalidaException();
        }
        UsuarioSesion usuario = usuarioSesionPort.buscarPorId(token.getIdUsuario())
                .filter(UsuarioSesion::habilitado)
                .orElse(null);
        if (usuario == null) {
            tokenRenovacionRepositoryPort.revocarFamilia(token.getFamilia(), ahora);
            throw new SesionInvalidaException();
        }
        if (!tokenRenovacionRepositoryPort.marcarUsado(token.getIdToken(), ahora)) {
            throw new SesionInvalidaException();
        }
        return emisionSesion.emitir(usuario.idUsuario(), usuario.rol(), token.getFamilia());
    }
}
