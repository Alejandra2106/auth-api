package com.crediticio.auth.sesiones.domain;

/** HU09 CA12: token de renovación inválido, expirado, revocado o reutilizado. */
public class SesionInvalidaException extends RuntimeException {

    public SesionInvalidaException() {
        super("La sesión no es válida");
    }
}
