package com.crediticio.auth.sesiones.ports.output;

import com.crediticio.auth.sesiones.domain.TokenRenovacion;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface TokenRenovacionRepositoryPort {

    void guardar(TokenRenovacion token);

    /** Bloquea la fila hasta el fin de la transacción: dos renovaciones con el mismo token se serializan. */
    Optional<TokenRenovacion> buscarPorHashParaActualizar(String hashToken);

    /** Actualización condicional: devuelve false si el token ya estaba usado o revocado. */
    boolean marcarUsado(UUID idToken, Instant ahora);

    void revocarFamilia(UUID familia, Instant ahora);
}
