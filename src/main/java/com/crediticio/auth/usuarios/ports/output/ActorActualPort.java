package com.crediticio.auth.usuarios.ports.output;

import java.util.Optional;
import java.util.UUID;

/** Identidad del usuario autenticado, sin que la aplicación dependa de Spring Security. */
public interface ActorActualPort {

    Optional<UUID> idActorAutenticado();
}
