package com.crediticio.auth.usuarios.ports.output;

import java.time.Instant;
import java.util.UUID;

public interface RevocarSesionesUsuarioPort {

    void revocarSesiones(UUID idUsuario, Instant ahora);
}
