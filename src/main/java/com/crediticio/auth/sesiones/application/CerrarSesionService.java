package com.crediticio.auth.sesiones.application;

import com.crediticio.auth.sesiones.ports.input.CerrarSesionUseCase;
import com.crediticio.auth.sesiones.ports.output.TokenRenovacionCriptografiaPort;
import com.crediticio.auth.sesiones.ports.output.TokenRenovacionRepositoryPort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;

/**
 * HU09 CA11: revoca la familia completa del token presentado. Los JWT de acceso ya emitidos
 * siguen siendo válidos hasta su expiración (máximo 15 minutos, HU10 CA10).
 */
@Service
public class CerrarSesionService implements CerrarSesionUseCase {

    private final TokenRenovacionRepositoryPort tokenRenovacionRepositoryPort;
    private final TokenRenovacionCriptografiaPort criptografiaPort;
    private final Clock clock;

    public CerrarSesionService(TokenRenovacionRepositoryPort tokenRenovacionRepositoryPort,
            TokenRenovacionCriptografiaPort criptografiaPort, Clock clock) {
        this.tokenRenovacionRepositoryPort = tokenRenovacionRepositoryPort;
        this.criptografiaPort = criptografiaPort;
        this.clock = clock;
    }

    @Override
    @Transactional
    public void cerrar(String tokenRenovacion) {
        if (tokenRenovacion == null || tokenRenovacion.isBlank()) {
            return;
        }
        tokenRenovacionRepositoryPort.buscarPorHashParaActualizar(criptografiaPort.hashear(tokenRenovacion))
                .ifPresent(token -> tokenRenovacionRepositoryPort.revocarFamilia(token.getFamilia(), Instant.now(clock)));
    }
}
