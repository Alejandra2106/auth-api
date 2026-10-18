package com.crediticio.auth.usuarios.application;

import com.crediticio.auth.usuarios.domain.CorreoElectronico;
import com.crediticio.auth.usuarios.domain.PoliticaContrasena;
import com.crediticio.auth.usuarios.domain.Rol;
import com.crediticio.auth.usuarios.domain.Usuario;
import com.crediticio.auth.usuarios.ports.input.RestablecerContrasenaAdministradorUseCase;
import com.crediticio.auth.usuarios.ports.output.HashContrasenaPort;
import com.crediticio.auth.usuarios.ports.output.RevocarSesionesUsuarioPort;
import com.crediticio.auth.usuarios.ports.output.UsuarioRepositoryPort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;

@Service
public class RestablecerContrasenaAdministradorService implements RestablecerContrasenaAdministradorUseCase {

    private final UsuarioRepositoryPort usuarioRepositoryPort;
    private final HashContrasenaPort hashContrasenaPort;
    private final RevocarSesionesUsuarioPort revocarSesionesUsuarioPort;
    private final Clock clock;

    public RestablecerContrasenaAdministradorService(UsuarioRepositoryPort usuarioRepositoryPort,
            HashContrasenaPort hashContrasenaPort, RevocarSesionesUsuarioPort revocarSesionesUsuarioPort,
            Clock clock) {
        this.usuarioRepositoryPort = usuarioRepositoryPort;
        this.hashContrasenaPort = hashContrasenaPort;
        this.revocarSesionesUsuarioPort = revocarSesionesUsuarioPort;
        this.clock = clock;
    }

    @Override
    @Transactional
    public void restablecer(String correo, String contrasena) {
        CorreoElectronico correoNormalizado = CorreoElectronico.de(correo);
        PoliticaContrasena.validar(contrasena);
        Usuario usuario = usuarioRepositoryPort.buscarPorCorreo(correoNormalizado)
                .orElseThrow(() -> new IllegalStateException("No existe un administrador con el correo indicado"));
        if (usuario.getRol() != Rol.ADMINISTRADOR_RIESGO) {
            throw new IllegalStateException("El correo indicado no pertenece a un administrador");
        }

        Usuario actualizado = Usuario.reconstruir(usuario.getIdUsuario(), usuario.getCorreo(),
                hashContrasenaPort.hashear(contrasena), usuario.getRol(), usuario.isHabilitado(),
                usuario.getFechaCreacion(), usuario.getCreadoPor(), usuario.getOrigenCreacion());
        usuarioRepositoryPort.guardar(actualizado);
        revocarSesionesUsuarioPort.revocarSesiones(usuario.getIdUsuario(), Instant.now(clock));
    }
}
