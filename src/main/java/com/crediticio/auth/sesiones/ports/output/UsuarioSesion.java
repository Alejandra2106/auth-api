package com.crediticio.auth.sesiones.ports.output;

import java.util.UUID;

/** Proyección mínima del usuario que necesita el módulo de sesiones. */
public record UsuarioSesion(UUID idUsuario, String hashContrasena, String rol, boolean habilitado) {

    @Override
    public String toString() {
        return "UsuarioSesion[idUsuario=" + idUsuario + ", rol=" + rol + ", habilitado=" + habilitado + "]";
    }
}
