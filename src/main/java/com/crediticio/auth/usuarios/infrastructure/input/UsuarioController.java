package com.crediticio.auth.usuarios.infrastructure.input;

import com.crediticio.auth.usuarios.application.dto.RegistrarUsuarioRequest;
import com.crediticio.auth.usuarios.application.dto.UsuarioResponse;
import com.crediticio.auth.usuarios.ports.input.RegistrarUsuarioUseCase;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/usuarios")
@Tag(name = "Usuarios", description = "Gestión de usuarios y roles (HU08)")
public class UsuarioController {

    private final RegistrarUsuarioUseCase registrarUsuarioUseCase;

    public UsuarioController(RegistrarUsuarioUseCase registrarUsuarioUseCase) {
        this.registrarUsuarioUseCase = registrarUsuarioUseCase;
    }

    @PostMapping
    @Operation(summary = "Registrar un usuario y asignarle un rol",
            description = "Solo ADMINISTRADOR_RIESGO. Responde 400, 401, 403 o 409 según corresponda.")
    public ResponseEntity<UsuarioResponse> registrar(@Valid @RequestBody RegistrarUsuarioRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(registrarUsuarioUseCase.registrar(request));
    }
}
