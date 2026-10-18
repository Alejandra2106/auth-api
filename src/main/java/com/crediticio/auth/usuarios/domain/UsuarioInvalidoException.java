package com.crediticio.auth.usuarios.domain;

/** Datos de usuario que incumplen las reglas del dominio. El mensaje nunca incluye la contraseña. */
public class UsuarioInvalidoException extends RuntimeException {

    public UsuarioInvalidoException(String mensaje) {
        super(mensaje);
    }
}
