package com.crediticio.auth.usuarios.ports.input;

import com.crediticio.auth.usuarios.application.dto.RegistrarUsuarioRequest;
import com.crediticio.auth.usuarios.application.dto.UsuarioResponse;

public interface RegistrarUsuarioUseCase {

    UsuarioResponse registrar(RegistrarUsuarioRequest request);
}
