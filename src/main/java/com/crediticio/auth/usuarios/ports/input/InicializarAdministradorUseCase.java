package com.crediticio.auth.usuarios.ports.input;

import java.util.UUID;

/** HU08 CA13: crea el primer administrador una sola vez, fuera de la API pública. */
public interface InicializarAdministradorUseCase {

    UUID inicializar(String correo, String contrasena);
}
