package com.crediticio.auth.usuarios.application;

import com.crediticio.auth.usuarios.domain.AdministradorYaInicializadoException;
import com.crediticio.auth.usuarios.domain.CorreoDuplicadoException;
import com.crediticio.auth.usuarios.domain.CorreoElectronico;
import com.crediticio.auth.usuarios.domain.PoliticaContrasena;
import com.crediticio.auth.usuarios.domain.Usuario;
import com.crediticio.auth.usuarios.ports.input.InicializarAdministradorUseCase;
import com.crediticio.auth.usuarios.ports.output.HashContrasenaPort;
import com.crediticio.auth.usuarios.ports.output.UsuarioRepositoryPort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * HU08 CA13. El bloqueo se toma antes de comprobar si ya existe un administrador, de modo que dos
 * ejecuciones simultáneas no pueden crear dos administradores iniciales.
 */
@Service
public class InicializarAdministradorService implements InicializarAdministradorUseCase {

    private final UsuarioRepositoryPort usuarioRepositoryPort;
    private final HashContrasenaPort hashContrasenaPort;
    private final Clock clock;

    public InicializarAdministradorService(UsuarioRepositoryPort usuarioRepositoryPort,
            HashContrasenaPort hashContrasenaPort, Clock clock) {
        this.usuarioRepositoryPort = usuarioRepositoryPort;
        this.hashContrasenaPort = hashContrasenaPort;
        this.clock = clock;
    }

    @Override
    @Transactional
    public UUID inicializar(String correo, String contrasena) {
        usuarioRepositoryPort.bloquearInicializacionAdministrador();
        if (usuarioRepositoryPort.existeAdministrador()) {
            throw new AdministradorYaInicializadoException();
        }
        CorreoElectronico correoNormalizado = CorreoElectronico.de(correo);
        PoliticaContrasena.validar(contrasena);
        if (usuarioRepositoryPort.existePorCorreo(correoNormalizado)) {
            throw new CorreoDuplicadoException();
        }
        Usuario administrador = Usuario.administradorInicial(UUID.randomUUID(), correoNormalizado,
                hashContrasenaPort.hashear(contrasena), Instant.now(clock));
        return usuarioRepositoryPort.guardar(administrador).getIdUsuario();
    }
}
