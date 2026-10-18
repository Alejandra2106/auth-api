package com.crediticio.auth.usuarios.infrastructure.output;

import com.crediticio.auth.usuarios.domain.OrigenCreacion;
import com.crediticio.auth.usuarios.domain.Rol;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "usuario")
public class UsuarioJpaEntity {

    @Id
    @Column(name = "id_usuario")
    private UUID idUsuario;

    @Column(name = "correo", nullable = false, length = 254)
    private String correo;

    @Column(name = "hash_contrasena", nullable = false, length = 255)
    private String hashContrasena;

    @Enumerated(EnumType.STRING)
    @Column(name = "rol", nullable = false, length = 30)
    private Rol rol;

    @Column(name = "habilitado", nullable = false)
    private boolean habilitado;

    @Column(name = "fecha_creacion", nullable = false, updatable = false)
    private Instant fechaCreacion;

    @Column(name = "creado_por", updatable = false)
    private UUID creadoPor;

    @Enumerated(EnumType.STRING)
    @Column(name = "origen_creacion", nullable = false, length = 20, updatable = false)
    private OrigenCreacion origenCreacion;

    protected UsuarioJpaEntity() {
        // requerido por JPA
    }

    public UsuarioJpaEntity(UUID idUsuario, String correo, String hashContrasena, Rol rol, boolean habilitado,
            Instant fechaCreacion, UUID creadoPor, OrigenCreacion origenCreacion) {
        this.idUsuario = idUsuario;
        this.correo = correo;
        this.hashContrasena = hashContrasena;
        this.rol = rol;
        this.habilitado = habilitado;
        this.fechaCreacion = fechaCreacion;
        this.creadoPor = creadoPor;
        this.origenCreacion = origenCreacion;
    }

    public UUID getIdUsuario() {
        return idUsuario;
    }

    public String getCorreo() {
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
}
