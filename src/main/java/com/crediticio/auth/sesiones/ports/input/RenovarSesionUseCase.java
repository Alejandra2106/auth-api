package com.crediticio.auth.sesiones.ports.input;

import com.crediticio.auth.sesiones.domain.SesionEmitida;

public interface RenovarSesionUseCase {

    SesionEmitida renovar(String tokenRenovacion);
}
