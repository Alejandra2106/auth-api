package com.crediticio.auth.sesiones.infrastructure.input;

public class OrigenNoPermitidoException extends RuntimeException {

    public OrigenNoPermitidoException() {
        super("El origen de la solicitud no está permitido");
    }
}
