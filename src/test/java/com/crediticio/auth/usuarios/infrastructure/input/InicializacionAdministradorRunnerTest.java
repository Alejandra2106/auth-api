package com.crediticio.auth.usuarios.infrastructure.input;

import com.crediticio.auth.usuarios.ports.input.InicializarAdministradorUseCase;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.DefaultApplicationArguments;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class InicializacionAdministradorRunnerTest {

    @TempDir
    Path directorio;

    @Test
    void debeLeerLaContrasenaDelArchivoSinElSaltoDeLineaFinal() throws Exception {
        Path archivo = directorio.resolve("contrasena.txt");
        Files.writeString(archivo, "contrasena con espacios \r\n", StandardCharsets.UTF_8);

        assertThat(InicializacionAdministradorRunner.leerContrasena(archivo)).isEqualTo("contrasena con espacios ");
    }

    @Test
    void debeIgnorarLaMarcaUtf8InicialDelArchivo() throws Exception {
        Path archivo = directorio.resolve("contrasena-con-bom.txt");
        Files.writeString(archivo, "\uFEFFcontrasena-segura\r\n", StandardCharsets.UTF_8);

        assertThat(InicializacionAdministradorRunner.leerContrasena(archivo)).isEqualTo("contrasena-segura");
    }

    @Test
    void debeInicializarConElCorreoYLaContrasenaDelArchivo() throws Exception {
        Path archivo = directorio.resolve("contrasena.txt");
        Files.writeString(archivo, "contrasena-inicial\n", StandardCharsets.UTF_8);
        InicializarAdministradorUseCase casoDeUso = mock(InicializarAdministradorUseCase.class);
        when(casoDeUso.inicializar("admin@ejemplo.com", "contrasena-inicial")).thenReturn(UUID.randomUUID());

        new InicializacionAdministradorRunner(casoDeUso, "admin@ejemplo.com", archivo.toString())
                .run(new DefaultApplicationArguments());

        verify(casoDeUso).inicializar("admin@ejemplo.com", "contrasena-inicial");
    }

    @Test
    void sinConfiguracionNoDebeInicializarNada() {
        InicializarAdministradorUseCase casoDeUso = mock(InicializarAdministradorUseCase.class);

        assertThatThrownBy(() -> new InicializacionAdministradorRunner(casoDeUso, "", "")
                .run(new DefaultApplicationArguments()))
                .isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(casoDeUso);
    }
}
