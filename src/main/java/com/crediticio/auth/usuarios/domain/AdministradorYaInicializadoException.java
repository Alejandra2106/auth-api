package com.crediticio.auth.usuarios.domain;

public class AdministradorYaInicializadoException extends RuntimeException {

    public AdministradorYaInicializadoException() {
        super("Ya existe un administrador de riesgo; la inicialización no se repite");
    }
}
