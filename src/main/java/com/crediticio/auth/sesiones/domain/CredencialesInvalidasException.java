package com.crediticio.auth.sesiones.domain;

/**
 * HU09 CA02: el mismo error para credenciales incorrectas, usuario inexistente o cuenta
 * deshabilitada, sin revelar cuál falló.
 */
public class CredencialesInvalidasException extends RuntimeException {

    public CredencialesInvalidasException() {
        super("Credenciales inválidas");
    }
}
