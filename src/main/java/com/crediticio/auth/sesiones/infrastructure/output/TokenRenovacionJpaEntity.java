package com.crediticio.auth.sesiones.infrastructure.output;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/** Sin setters: los cambios de estado se hacen con actualizaciones condicionales del repositorio. */
@Entity
@Table(name = "token_renovacion")
public class TokenRenovacionJpaEntity {

    @Id
    @Column(name = "id_token")
    private UUID idToken;

    @Column(name = "id_usuario", nullable = false, updatable = false)
    private UUID idUsuario;

    @Column(name = "familia", nullable = false, updatable = false)
    private UUID familia;

    @Column(name = "hash_token", nullable = false, length = 64, updatable = false)
    private String hashToken;

    @Column(name = "emitido_en", nullable = false, updatable = false)
    private Instant emitidoEn;

    @Column(name = "expira_en", nullable = false, updatable = false)
    private Instant expiraEn;

    @Column(name = "usado_en")
    private Instant usadoEn;

    @Column(name = "revocado_en")
    private Instant revocadoEn;

    protected TokenRenovacionJpaEntity() {
        // requerido por JPA
    }

    public TokenRenovacionJpaEntity(UUID idToken, UUID idUsuario, UUID familia, String hashToken, Instant emitidoEn,
            Instant expiraEn) {
        this.idToken = idToken;
        this.idUsuario = idUsuario;
        this.familia = familia;
        this.hashToken = hashToken;
        this.emitidoEn = emitidoEn;
        this.expiraEn = expiraEn;
    }

    public UUID getIdToken() {
        return idToken;
    }

    public UUID getIdUsuario() {
        return idUsuario;
    }

    public UUID getFamilia() {
        return familia;
    }

    public String getHashToken() {
        return hashToken;
    }

    public Instant getEmitidoEn() {
        return emitidoEn;
    }

    public Instant getExpiraEn() {
        return expiraEn;
    }

    public Instant getUsadoEn() {
        return usadoEn;
    }

    public Instant getRevocadoEn() {
        return revocadoEn;
    }
}
