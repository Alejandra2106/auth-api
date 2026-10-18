package com.crediticio.auth.usuarios.infrastructure.output;

import com.crediticio.auth.usuarios.ports.output.ActorActualPort;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

/** El autor se toma del claim "sub" del JWT validado, nunca de datos enviados por el cliente. */
@Component
public class SecurityContextActorActualAdapter implements ActorActualPort {

    @Override
    public Optional<UUID> idActorAutenticado() {
        Authentication autenticacion = SecurityContextHolder.getContext().getAuthentication();
        if (autenticacion == null || !(autenticacion.getPrincipal() instanceof Jwt jwt)) {
            return Optional.empty();
        }
        try {
            return Optional.of(UUID.fromString(jwt.getSubject()));
        } catch (IllegalArgumentException | NullPointerException ex) {
            return Optional.empty();
        }
    }
}
