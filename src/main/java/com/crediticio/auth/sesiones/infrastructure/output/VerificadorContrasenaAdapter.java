package com.crediticio.auth.sesiones.infrastructure.output;

import com.crediticio.auth.sesiones.ports.output.VerificadorContrasenaPort;
import com.crediticio.auth.usuarios.ports.output.HashContrasenaPort;
import org.springframework.stereotype.Component;

@Component
public class VerificadorContrasenaAdapter implements VerificadorContrasenaPort {

    private final HashContrasenaPort hashContrasenaPort;

    public VerificadorContrasenaAdapter(HashContrasenaPort hashContrasenaPort) {
        this.hashContrasenaPort = hashContrasenaPort;
    }

    @Override
    public boolean coincide(String contrasena, String hash) {
        return hashContrasenaPort.coincide(contrasena, hash);
    }

    @Override
    public void verificarSinUsuario(String contrasena) {
        hashContrasenaPort.coincide(contrasena, hashContrasenaPort.hashFicticio());
    }
}
