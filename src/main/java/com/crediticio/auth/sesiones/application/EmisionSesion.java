package com.crediticio.auth.sesiones.application;

import com.crediticio.auth.sesiones.domain.SesionEmitida;
import com.crediticio.auth.sesiones.domain.TokenAcceso;
import com.crediticio.auth.sesiones.domain.TokenRenovacion;
import com.crediticio.auth.sesiones.ports.output.EmisorTokenAccesoPort;
import com.crediticio.auth.sesiones.ports.output.TokenRenovacionCriptografiaPort;
import com.crediticio.auth.sesiones.ports.output.TokenRenovacionRepositoryPort;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Emite el par de tokens de una sesión (inicio o renovación): guarda solo el hash del token de
 * renovación y devuelve su valor en claro una única vez.
 */
@Component
class EmisionSesion {

    private final TokenRenovacionRepositoryPort tokenRenovacionRepositoryPort;
    private final TokenRenovacionCriptografiaPort criptografiaPort;
    private final EmisorTokenAccesoPort emisorTokenAccesoPort;
    private final Duration vigenciaRenovacion;
    private final Clock clock;

    EmisionSesion(TokenRenovacionRepositoryPort tokenRenovacionRepositoryPort,
            TokenRenovacionCriptografiaPort criptografiaPort, EmisorTokenAccesoPort emisorTokenAccesoPort,
            @Value("${auth.sesion.duracion-renovacion:7d}") Duration vigenciaRenovacion, Clock clock) {
        this.tokenRenovacionRepositoryPort = tokenRenovacionRepositoryPort;
        this.criptografiaPort = criptografiaPort;
        this.emisorTokenAccesoPort = emisorTokenAccesoPort;
        this.vigenciaRenovacion = vigenciaRenovacion;
        this.clock = clock;
    }

    SesionEmitida emitir(UUID idUsuario, String rol, UUID familia) {
        String tokenEnClaro = criptografiaPort.generar();
        tokenRenovacionRepositoryPort.guardar(TokenRenovacion.emitir(idUsuario, familia,
                criptografiaPort.hashear(tokenEnClaro), Instant.now(clock), vigenciaRenovacion));
        TokenAcceso tokenAcceso = emisorTokenAccesoPort.emitir(idUsuario, rol);
        return new SesionEmitida(tokenAcceso, tokenEnClaro, vigenciaRenovacion);
    }
}
