package com.crediticio.auth.usuarios.domain;

/** La operación exige un usuario autenticado que quede registrado como autor (HU08 CA07, CA11). */
public class ActorRequeridoException extends RuntimeException {

    public ActorRequeridoException() {
        super("La operación requiere un usuario autenticado");
    }
}
