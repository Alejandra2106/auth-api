package com.crediticio.auth.sesiones.infrastructure.output;

import com.crediticio.auth.sesiones.domain.TokenRenovacion;
import com.crediticio.auth.sesiones.ports.output.TokenRenovacionRepositoryPort;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Component
public class TokenRenovacionRepositoryAdapter implements TokenRenovacionRepositoryPort {

    private final TokenRenovacionJpaRepository tokenRenovacionJpaRepository;

    public TokenRenovacionRepositoryAdapter(TokenRenovacionJpaRepository tokenRenovacionJpaRepository) {
        this.tokenRenovacionJpaRepository = tokenRenovacionJpaRepository;
    }

    @Override
    public void guardar(TokenRenovacion token) {
        tokenRenovacionJpaRepository.saveAndFlush(new TokenRenovacionJpaEntity(token.getIdToken(),
                token.getIdUsuario(), token.getFamilia(), token.getHashToken(), token.getEmitidoEn(),
                token.getExpiraEn()));
    }

    @Override
    public Optional<TokenRenovacion> buscarPorHashParaActualizar(String hashToken) {
        return tokenRenovacionJpaRepository.findByHashToken(hashToken).map(entidad -> TokenRenovacion.reconstruir(
                entidad.getIdToken(), entidad.getIdUsuario(), entidad.getFamilia(), entidad.getHashToken(),
                entidad.getEmitidoEn(), entidad.getExpiraEn(), entidad.getUsadoEn(), entidad.getRevocadoEn()));
    }

    @Override
    public boolean marcarUsado(UUID idToken, Instant ahora) {
        return tokenRenovacionJpaRepository.marcarUsado(idToken, ahora) == 1;
    }

    @Override
    public void revocarFamilia(UUID familia, Instant ahora) {
        tokenRenovacionJpaRepository.revocarFamilia(familia, ahora);
    }
}
