package com.crediticio.auth.usuarios.infrastructure.output;

import com.crediticio.auth.usuarios.domain.CorreoDuplicadoException;
import com.crediticio.auth.usuarios.domain.CorreoElectronico;
import com.crediticio.auth.usuarios.domain.Rol;
import com.crediticio.auth.usuarios.domain.Usuario;
import com.crediticio.auth.usuarios.ports.output.UsuarioRepositoryPort;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

@Component
public class UsuarioRepositoryAdapter implements UsuarioRepositoryPort {

    /** Clave del bloqueo consultivo de PostgreSQL que serializa la inicialización del administrador. */
    static final long CLAVE_BLOQUEO_INICIALIZACION = 0x41555448_0001L;
    private static final String RESTRICCION_CORREO_UNICO = "uq_usuario_correo";

    private final UsuarioJpaRepository usuarioJpaRepository;

    @PersistenceContext
    private EntityManager entityManager;

    public UsuarioRepositoryAdapter(UsuarioJpaRepository usuarioJpaRepository) {
        this.usuarioJpaRepository = usuarioJpaRepository;
    }

    @Override
    public Usuario guardar(Usuario usuario) {
        try {
            return aDominio(usuarioJpaRepository.saveAndFlush(aEntidad(usuario)));
        } catch (DataIntegrityViolationException ex) {
            if (esViolacionDeCorreoUnico(ex)) {
                throw new CorreoDuplicadoException();
            }
            throw ex;
        }
    }

    @Override
    public boolean existePorCorreo(CorreoElectronico correo) {
        return usuarioJpaRepository.existsByCorreo(correo.valor());
    }

    @Override
    public Optional<Usuario> buscarPorCorreo(CorreoElectronico correo) {
        return usuarioJpaRepository.findByCorreo(correo.valor()).map(this::aDominio);
    }

    @Override
    public Optional<Usuario> buscarPorId(UUID idUsuario) {
        return usuarioJpaRepository.findById(idUsuario).map(this::aDominio);
    }

    @Override
    public boolean existeAdministrador() {
        return usuarioJpaRepository.existsByRol(Rol.ADMINISTRADOR_RIESGO);
    }

    @Override
    public void bloquearInicializacionAdministrador() {
        // bloqueo de transacción: se libera solo al confirmar o revertir
        entityManager.createNativeQuery("SELECT pg_advisory_xact_lock(:clave)")
                .setParameter("clave", CLAVE_BLOQUEO_INICIALIZACION)
                .getSingleResult();
    }

    private static boolean esViolacionDeCorreoUnico(DataIntegrityViolationException ex) {
        String mensaje = ex.getMostSpecificCause().getMessage();
        return mensaje != null && mensaje.toLowerCase(Locale.ROOT).contains(RESTRICCION_CORREO_UNICO);
    }

    private UsuarioJpaEntity aEntidad(Usuario usuario) {
        return new UsuarioJpaEntity(usuario.getIdUsuario(), usuario.getCorreo().valor(), usuario.getHashContrasena(),
                usuario.getRol(), usuario.isHabilitado(), usuario.getFechaCreacion(), usuario.getCreadoPor(),
                usuario.getOrigenCreacion());
    }

    private Usuario aDominio(UsuarioJpaEntity entidad) {
        return Usuario.reconstruir(entidad.getIdUsuario(), new CorreoElectronico(entidad.getCorreo()),
                entidad.getHashContrasena(), entidad.getRol(), entidad.isHabilitado(), entidad.getFechaCreacion(),
                entidad.getCreadoPor(), entidad.getOrigenCreacion());
    }
}
