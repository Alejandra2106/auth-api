package com.crediticio.auth.sesiones.infrastructure.output;

import com.crediticio.auth.usuarios.ports.output.RevocarSesionesUsuarioPort;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.UUID;

@Component
public class RevocarSesionesUsuarioAdapter implements RevocarSesionesUsuarioPort {

    private final TokenRenovacionJpaRepository tokenRenovacionJpaRepository;

    public RevocarSesionesUsuarioAdapter(TokenRenovacionJpaRepository tokenRenovacionJpaRepository) {
        this.tokenRenovacionJpaRepository = tokenRenovacionJpaRepository;
    }

    @Override
    public void revocarSesiones(UUID idUsuario, Instant ahora) {
        tokenRenovacionJpaRepository.revocarSesionesUsuario(idUsuario, ahora);
    }
}
