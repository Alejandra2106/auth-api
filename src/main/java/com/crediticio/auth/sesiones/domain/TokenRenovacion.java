package com.crediticio.auth.sesiones.domain;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Token de renovación de un solo uso. Solo se conserva su hash (HU09 CA07). Todos los tokens
 * obtenidos por rotación a partir de un mismo inicio de sesión comparten la familia, que se revoca
 * completa si se reutiliza un token ya rotado (CA10).
 */
public final class TokenRenovacion {

    /** HU09 CA06. */
    public static final Duration VIGENCIA_MAXIMA = Duration.ofDays(7);

    private final UUID idToken;
    private final UUID idUsuario;
    private final UUID familia;
    private final String hashToken;
    private final Instant emitidoEn;
    private final Instant expiraEn;
    private final Instant usadoEn;
    private final Instant revocadoEn;

    private TokenRenovacion(UUID idToken, UUID idUsuario, UUID familia, String hashToken, Instant emitidoEn,
            Instant expiraEn, Instant usadoEn, Instant revocadoEn) {
        this.idToken = Objects.requireNonNull(idToken, "idToken es obligatorio");
        this.idUsuario = Objects.requireNonNull(idUsuario, "idUsuario es obligatorio");
        this.familia = Objects.requireNonNull(familia, "familia es obligatoria");
        if (hashToken == null || hashToken.isBlank()) {
            throw new IllegalArgumentException("hashToken es obligatorio");
        }
        this.hashToken = hashToken;
        this.emitidoEn = Objects.requireNonNull(emitidoEn, "emitidoEn es obligatorio");
        this.expiraEn = Objects.requireNonNull(expiraEn, "expiraEn es obligatorio");
        if (!expiraEn.isAfter(emitidoEn) || Duration.between(emitidoEn, expiraEn).compareTo(VIGENCIA_MAXIMA) > 0) {
            throw new IllegalArgumentException("La vigencia del token de renovación debe ser positiva y de "
                    + "máximo " + VIGENCIA_MAXIMA.toDays() + " días");
        }
        this.usadoEn = usadoEn;
        this.revocadoEn = revocadoEn;
    }

    public static TokenRenovacion emitir(UUID idUsuario, UUID familia, String hashToken, Instant ahora,
            Duration vigencia) {
        Objects.requireNonNull(vigencia, "vigencia es obligatoria");
        return new TokenRenovacion(UUID.randomUUID(), idUsuario, familia, hashToken, ahora, ahora.plus(vigencia),
                null, null);
    }

    public static TokenRenovacion reconstruir(UUID idToken, UUID idUsuario, UUID familia, String hashToken,
            Instant emitidoEn, Instant expiraEn, Instant usadoEn, Instant revocadoEn) {
        return new TokenRenovacion(idToken, idUsuario, familia, hashToken, emitidoEn, expiraEn, usadoEn, revocadoEn);
    }

    /** La revocación prevalece sobre el uso, y el uso sobre la expiración. */
    public EstadoTokenRenovacion estado(Instant ahora) {
        if (revocadoEn != null) {
            return EstadoTokenRenovacion.REVOCADO;
        }
        if (usadoEn != null) {
            return EstadoTokenRenovacion.USADO;
        }
        if (!ahora.isBefore(expiraEn)) {
            return EstadoTokenRenovacion.EXPIRADO;
        }
        return EstadoTokenRenovacion.VIGENTE;
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

    @Override
    public String toString() {
        return "TokenRenovacion[idToken=" + idToken + ", familia=" + familia + "]";
    }
}
