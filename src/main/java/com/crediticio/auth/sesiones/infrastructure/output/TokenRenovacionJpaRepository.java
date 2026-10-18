package com.crediticio.auth.sesiones.infrastructure.output;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface TokenRenovacionJpaRepository extends JpaRepository<TokenRenovacionJpaEntity, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<TokenRenovacionJpaEntity> findByHashToken(String hashToken);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update TokenRenovacionJpaEntity t set t.usadoEn = :ahora "
            + "where t.idToken = :idToken and t.usadoEn is null and t.revocadoEn is null")
    int marcarUsado(@Param("idToken") UUID idToken, @Param("ahora") Instant ahora);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update TokenRenovacionJpaEntity t set t.revocadoEn = :ahora "
            + "where t.familia = :familia and t.revocadoEn is null")
    int revocarFamilia(@Param("familia") UUID familia, @Param("ahora") Instant ahora);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update TokenRenovacionJpaEntity t set t.revocadoEn = :ahora "
            + "where t.idUsuario = :idUsuario and t.revocadoEn is null")
    int revocarSesionesUsuario(@Param("idUsuario") UUID idUsuario, @Param("ahora") Instant ahora);
}
