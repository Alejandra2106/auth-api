package com.crediticio.auth.usuarios.ports.output;

public interface HashContrasenaPort {

    String hashear(String contrasena);

    /** Nunca lanza por contraseñas con formato inesperado: simplemente no coinciden. */
    boolean coincide(String contrasena, String hash);

    /** Hash válido sin usuario asociado, para igualar el tiempo de respuesta ante usuarios inexistentes. */
    String hashFicticio();
}
