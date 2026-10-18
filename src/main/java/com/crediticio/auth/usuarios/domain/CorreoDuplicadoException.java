package com.crediticio.auth.usuarios.domain;

public class CorreoDuplicadoException extends RuntimeException {

    public CorreoDuplicadoException() {
        super("Ya existe un usuario registrado con ese correo");
    }
}
