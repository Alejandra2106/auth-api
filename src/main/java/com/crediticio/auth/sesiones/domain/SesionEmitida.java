package com.crediticio.auth.sesiones.domain;

import java.time.Duration;

/** El token de renovación en claro solo existe aquí, para entregarlo en la cookie; nunca se persiste. */
public record SesionEmitida(TokenAcceso tokenAcceso, String tokenRenovacion, Duration vigenciaRenovacion) {

    @Override
    public String toString() {
        return "SesionEmitida[" + tokenAcceso + "]";
    }
}
