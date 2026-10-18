package com.crediticio.auth.sesiones.ports.output;

import java.util.Optional;
import java.util.UUID;

public interface UsuarioSesionPort {

    /** Normaliza el correo; un correo con formato inválido se trata como inexistente. */
    Optional<UsuarioSesion> buscarPorCorreo(String correo);

    Optional<UsuarioSesion> buscarPorId(UUID idUsuario);
}
