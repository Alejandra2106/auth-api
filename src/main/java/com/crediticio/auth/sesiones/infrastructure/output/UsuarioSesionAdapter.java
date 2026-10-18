package com.crediticio.auth.sesiones.infrastructure.output;

import com.crediticio.auth.sesiones.ports.output.UsuarioSesion;
import com.crediticio.auth.sesiones.ports.output.UsuarioSesionPort;
import com.crediticio.auth.usuarios.domain.CorreoElectronico;
import com.crediticio.auth.usuarios.domain.Usuario;
import com.crediticio.auth.usuarios.domain.UsuarioInvalidoException;
import com.crediticio.auth.usuarios.ports.output.UsuarioRepositoryPort;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

/** Único punto del módulo de sesiones que conoce el módulo de usuarios. */
@Component
public class UsuarioSesionAdapter implements UsuarioSesionPort {

    private final UsuarioRepositoryPort usuarioRepositoryPort;

    public UsuarioSesionAdapter(UsuarioRepositoryPort usuarioRepositoryPort) {
        this.usuarioRepositoryPort = usuarioRepositoryPort;
    }

    @Override
    public Optional<UsuarioSesion> buscarPorCorreo(String correo) {
        CorreoElectronico correoNormalizado;
        try {
            correoNormalizado = CorreoElectronico.de(correo);
        } catch (UsuarioInvalidoException ex) {
            return Optional.empty();
        }
        return usuarioRepositoryPort.buscarPorCorreo(correoNormalizado).map(UsuarioSesionAdapter::aProyeccion);
    }

    @Override
    public Optional<UsuarioSesion> buscarPorId(UUID idUsuario) {
        return usuarioRepositoryPort.buscarPorId(idUsuario).map(UsuarioSesionAdapter::aProyeccion);
    }

    private static UsuarioSesion aProyeccion(Usuario usuario) {
        return new UsuarioSesion(usuario.getIdUsuario(), usuario.getHashContrasena(), usuario.getRol().name(),
                usuario.isHabilitado());
    }
}
