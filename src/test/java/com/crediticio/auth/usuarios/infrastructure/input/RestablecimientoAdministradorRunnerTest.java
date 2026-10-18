package com.crediticio.auth.usuarios.infrastructure.input;

import com.crediticio.auth.usuarios.ports.input.RestablecerContrasenaAdministradorUseCase;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.DefaultApplicationArguments;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class RestablecimientoAdministradorRunnerTest {

    @TempDir
    Path directorio;

    @Test
    void debeLeerLaContrasenaDelArchivoYRestablecerLaCuentaIndicada() throws Exception {
        Path archivo = directorio.resolve("nueva-contrasena.txt");
        Files.writeString(archivo, "nueva-contrasena-segura\r\n", StandardCharsets.UTF_8);
        RestablecerContrasenaAdministradorUseCase casoDeUso = mock(RestablecerContrasenaAdministradorUseCase.class);

        new RestablecimientoAdministradorRunner(casoDeUso, "admin@ejemplo.com", archivo.toString())
                .run(new DefaultApplicationArguments());

        verify(casoDeUso).restablecer("admin@ejemplo.com", "nueva-contrasena-segura");
    }

    @Test
    void sinConfiguracionNoDebeRestablecerLaCuenta() {
        RestablecerContrasenaAdministradorUseCase casoDeUso = mock(RestablecerContrasenaAdministradorUseCase.class);

        assertThatThrownBy(() -> new RestablecimientoAdministradorRunner(casoDeUso, "", "")
                .run(new DefaultApplicationArguments()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("AUTH_ADMIN_RESET_CORREO");
        verifyNoInteractions(casoDeUso);
    }
}
