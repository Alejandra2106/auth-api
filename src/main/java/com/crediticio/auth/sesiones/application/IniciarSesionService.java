package com.crediticio.auth.sesiones.application;

import com.crediticio.auth.sesiones.domain.CredencialesInvalidasException;
import com.crediticio.auth.sesiones.domain.SesionEmitida;
import com.crediticio.auth.sesiones.ports.input.IniciarSesionUseCase;
import com.crediticio.auth.sesiones.ports.output.UsuarioSesion;
import com.crediticio.auth.sesiones.ports.output.UsuarioSesionPort;
import com.crediticio.auth.sesiones.ports.output.VerificadorContrasenaPort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

/**
 * HU09 CA01–CA03. Usuario inexistente, contraseña incorrecta y cuenta deshabilitada producen el
 * mismo error; la contraseña se verifica siempre (también con un hash ficticio) para no revelar
 * por el tiempo de respuesta cuál de las condiciones falló.
 */
@Service
public class IniciarSesionService implements IniciarSesionUseCase {

    private final UsuarioSesionPort usuarioSesionPort;
    private final VerificadorContrasenaPort verificadorContrasenaPort;
    private final EmisionSesion emisionSesion;

    public IniciarSesionService(UsuarioSesionPort usuarioSesionPort, VerificadorContrasenaPort verificadorContrasenaPort,
            EmisionSesion emisionSesion) {
        this.usuarioSesionPort = usuarioSesionPort;
        this.verificadorContrasenaPort = verificadorContrasenaPort;
        this.emisionSesion = emisionSesion;
    }

    @Override
    @Transactional
    public SesionEmitida iniciar(String correo, String contrasena) {
        Optional<UsuarioSesion> usuario = correo == null ? Optional.empty() : usuarioSesionPort.buscarPorCorreo(correo);
        if (usuario.isEmpty()) {
            verificadorContrasenaPort.verificarSinUsuario(contrasena);
            throw new CredencialesInvalidasException();
        }
        boolean contrasenaCorrecta = verificadorContrasenaPort.coincide(contrasena, usuario.get().hashContrasena());
        if (!contrasenaCorrecta || !usuario.get().habilitado()) {
            throw new CredencialesInvalidasException();
        }
        return emisionSesion.emitir(usuario.get().idUsuario(), usuario.get().rol(), UUID.randomUUID());
    }
}
