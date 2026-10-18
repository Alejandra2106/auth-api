package com.crediticio.auth.usuarios.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Usuario con un único rol. Solo guarda el hash de la contraseña (HU08 CA05); el texto plano
 * nunca llega al dominio. El autor es obligatorio para las altas por API y nulo para el
 * administrador inicial (CA11, CA13).
 */
public final class Usuario {

    private final UUID idUsuario;
    private final CorreoElectronico correo;
    private final String hashContrasena;
    private final Rol rol;
    private final boolean habilitado;
    private final Instant fechaCreacion;
    private final UUID creadoPor;
    private final OrigenCreacion origenCreacion;

    private Usuario(UUID idUsuario, CorreoElectronico correo, String hashContrasena, Rol rol, boolean habilitado,
            Instant fechaCreacion, UUID creadoPor, OrigenCreacion origenCreacion) {
        this.idUsuario = Objects.requireNonNull(idUsuario, "idUsuario es obligatorio");
        this.correo = Objects.requireNonNull(correo, "correo es obligatorio");
        if (hashContrasena == null || hashContrasena.isBlank()) {
            throw new IllegalArgumentException("hashContrasena es obligatorio");
        }
        if (rol == null) {
            throw new UsuarioInvalidoException("rol es obligatorio");
        }
        this.hashContrasena = hashContrasena;
        this.rol = rol;
        this.habilitado = habilitado;
        this.fechaCreacion = Objects.requireNonNull(fechaCreacion, "fechaCreacion es obligatoria");
        this.origenCreacion = Objects.requireNonNull(origenCreacion, "origenCreacion es obligatorio");
        if ((origenCreacion == OrigenCreacion.API) != (creadoPor != null)) {
            throw new IllegalArgumentException("creadoPor es obligatorio solo para las altas por API");
        }
        this.creadoPor = creadoPor;
    }

    public static Usuario nuevo(UUID idUsuario, CorreoElectronico correo, String hashContrasena, Rol rol,
            Instant fechaCreacion, UUID creadoPor) {
        return new Usuario(idUsuario, correo, hashContrasena, rol, true, fechaCreacion,
                Objects.requireNonNull(creadoPor, "creadoPor es obligatorio"), OrigenCreacion.API);
    }

    public static Usuario administradorInicial(UUID idUsuario, CorreoElectronico correo, String hashContrasena,
            Instant fechaCreacion) {
        return new Usuario(idUsuario, correo, hashContrasena, Rol.ADMINISTRADOR_RIESGO, true, fechaCreacion,
                null, OrigenCreacion.INICIALIZACION);
    }

    public static Usuario reconstruir(UUID idUsuario, CorreoElectronico correo, String hashContrasena, Rol rol,
            boolean habilitado, Instant fechaCreacion, UUID creadoPor, OrigenCreacion origenCreacion) {
        return new Usuario(idUsuario, correo, hashContrasena, rol, habilitado, fechaCreacion, creadoPor,
                origenCreacion);
    }

    public UUID getIdUsuario() {
        return idUsuario;
    }

    public CorreoElectronico getCorreo() {
        return correo;
    }

    public String getHashContrasena() {
        return hashContrasena;
    }

    public Rol getRol() {
        return rol;
    }

    public boolean isHabilitado() {
        return habilitado;
    }

    public Instant getFechaCreacion() {
        return fechaCreacion;
    }

    public UUID getCreadoPor() {
        return creadoPor;
    }

    public OrigenCreacion getOrigenCreacion() {
        return origenCreacion;
    }

    @Override
    public String toString() {
        // sin el hash: el objeto puede terminar en un log
        return "Usuario[idUsuario=" + idUsuario + ", rol=" + rol + ", habilitado=" + habilitado + "]";
    }
}
