package com.crediticio.auth.sesiones.ports.output;

import com.crediticio.auth.sesiones.domain.TokenAcceso;

import java.util.UUID;

public interface EmisorTokenAccesoPort {

    TokenAcceso emitir(UUID idUsuario, String rol);
}
