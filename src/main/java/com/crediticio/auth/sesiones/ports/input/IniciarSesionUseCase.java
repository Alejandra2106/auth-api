package com.crediticio.auth.sesiones.ports.input;

import com.crediticio.auth.sesiones.domain.SesionEmitida;

public interface IniciarSesionUseCase {

    SesionEmitida iniciar(String correo, String contrasena);
}
