package com.crediticio.auth.usuarios.application.dto;

import com.crediticio.auth.usuarios.domain.Rol;

import java.time.Instant;
import java.util.UUID;

/** HU08 CA10: identificador, correo normalizado y rol; nunca la contraseña ni su hash. */
public record UsuarioResponse(UUID idUsuario, String correo, Rol rol, Instant fechaCreacion) {
}
