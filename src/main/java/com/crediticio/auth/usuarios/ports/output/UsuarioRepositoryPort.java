package com.crediticio.auth.usuarios.ports.output;

import com.crediticio.auth.usuarios.domain.CorreoElectronico;
import com.crediticio.auth.usuarios.domain.Usuario;

import java.util.Optional;
import java.util.UUID;

public interface UsuarioRepositoryPort {

    /** Lanza CorreoDuplicadoException si otro registro concurrente ya tomó el correo (CA03). */
    Usuario guardar(Usuario usuario);

    boolean existePorCorreo(CorreoElectronico correo);

    Optional<Usuario> buscarPorCorreo(CorreoElectronico correo);

    Optional<Usuario> buscarPorId(UUID idUsuario);

    boolean existeAdministrador();

    /** Serializa la inicialización del primer administrador hasta el fin de la transacción. */
    void bloquearInicializacionAdministrador();
}
