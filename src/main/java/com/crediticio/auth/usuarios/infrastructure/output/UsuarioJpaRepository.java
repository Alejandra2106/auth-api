package com.crediticio.auth.usuarios.infrastructure.output;

import com.crediticio.auth.usuarios.domain.Rol;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UsuarioJpaRepository extends JpaRepository<UsuarioJpaEntity, UUID> {

    boolean existsByCorreo(String correo);

    Optional<UsuarioJpaEntity> findByCorreo(String correo);

    boolean existsByRol(Rol rol);
}
