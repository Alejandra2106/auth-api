package com.crediticio.auth.usuarios.application.dto;

import com.crediticio.auth.usuarios.domain.Rol;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record RegistrarUsuarioRequest(
        @NotBlank(message = "correo es obligatorio") String correo,
        @NotBlank(message = "contrasena es obligatoria") String contrasena,
        @NotNull(message = "rol es obligatorio") Rol rol) {

    @Override
    public String toString() {
        // nunca expone la contraseña si el objeto termina en un log
        return "RegistrarUsuarioRequest[rol=" + rol + "]";
    }
}
