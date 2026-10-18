package com.crediticio.auth.usuarios.application;

import com.crediticio.auth.usuarios.application.dto.RegistrarUsuarioRequest;
import com.crediticio.auth.usuarios.application.dto.UsuarioResponse;
import com.crediticio.auth.usuarios.domain.ActorRequeridoException;
import com.crediticio.auth.usuarios.domain.CorreoDuplicadoException;
import com.crediticio.auth.usuarios.domain.CorreoElectronico;
import com.crediticio.auth.usuarios.domain.PoliticaContrasena;
import com.crediticio.auth.usuarios.domain.Usuario;
import com.crediticio.auth.usuarios.ports.input.RegistrarUsuarioUseCase;
import com.crediticio.auth.usuarios.ports.output.ActorActualPort;
import com.crediticio.auth.usuarios.ports.output.HashContrasenaPort;
import com.crediticio.auth.usuarios.ports.output.UsuarioRepositoryPort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * HU08: el control de que solo un administrador invoque este caso de uso está en la seguridad
 * del endpoint (HU10); aquí se exige además un actor autenticado para registrarlo como autor.
 * El usuario y su rol se guardan en un único INSERT dentro de la transacción (CA09).
 */
@Service
public class RegistrarUsuarioService implements RegistrarUsuarioUseCase {

    private final UsuarioRepositoryPort usuarioRepositoryPort;
    private final HashContrasenaPort hashContrasenaPort;
    private final ActorActualPort actorActualPort;
    private final UsuarioMapper usuarioMapper;
    private final Clock clock;

    public RegistrarUsuarioService(UsuarioRepositoryPort usuarioRepositoryPort, HashContrasenaPort hashContrasenaPort,
            ActorActualPort actorActualPort, UsuarioMapper usuarioMapper, Clock clock) {
        this.usuarioRepositoryPort = usuarioRepositoryPort;
        this.hashContrasenaPort = hashContrasenaPort;
        this.actorActualPort = actorActualPort;
        this.usuarioMapper = usuarioMapper;
        this.clock = clock;
    }

    @Override
    @Transactional
    public UsuarioResponse registrar(RegistrarUsuarioRequest request) {
        Objects.requireNonNull(request, "request es obligatorio");
        UUID autor = actorActualPort.idActorAutenticado().orElseThrow(ActorRequeridoException::new);
        CorreoElectronico correo = CorreoElectronico.de(request.correo());
        PoliticaContrasena.validar(request.contrasena());
        if (usuarioRepositoryPort.existePorCorreo(correo)) {
            throw new CorreoDuplicadoException();
        }
        Usuario usuario = Usuario.nuevo(UUID.randomUUID(), correo, hashContrasenaPort.hashear(request.contrasena()),
                request.rol(), Instant.now(clock), autor);
        return usuarioMapper.aResponse(usuarioRepositoryPort.guardar(usuario));
    }
}
