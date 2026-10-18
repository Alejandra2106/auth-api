package com.crediticio.auth.usuarios.ports.input;

public interface RestablecerContrasenaAdministradorUseCase {

    void restablecer(String correo, String contrasena);
}
