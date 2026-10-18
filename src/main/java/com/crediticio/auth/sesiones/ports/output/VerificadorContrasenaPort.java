package com.crediticio.auth.sesiones.ports.output;

public interface VerificadorContrasenaPort {

    boolean coincide(String contrasena, String hash);

    /** Consume el mismo tiempo que una verificación real cuando el usuario no existe (HU09 CA02). */
    void verificarSinUsuario(String contrasena);
}
