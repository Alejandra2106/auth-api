package com.crediticio.auth.usuarios.application;

import com.crediticio.auth.usuarios.application.dto.UsuarioResponse;
import com.crediticio.auth.usuarios.domain.Usuario;
import org.springframework.stereotype.Component;

@Component
public class UsuarioMapper {

    public UsuarioResponse aResponse(Usuario usuario) {
        return new UsuarioResponse(usuario.getIdUsuario(), usuario.getCorreo().valor(), usuario.getRol(),
                usuario.getFechaCreacion());
    }
}
