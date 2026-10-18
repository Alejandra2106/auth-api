package com.crediticio.auth.sesiones.application.dto;

import jakarta.validation.constraints.NotBlank;

public record IniciarSesionRequest(
        @NotBlank(message = "correo es obligatorio") String correo,
        @NotBlank(message = "contrasena es obligatoria") String contrasena) {

    @Override
    public String toString() {
        return "IniciarSesionRequest[]";
    }
}
