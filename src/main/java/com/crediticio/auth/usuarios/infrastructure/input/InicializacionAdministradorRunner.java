package com.crediticio.auth.usuarios.infrastructure.input;

import com.crediticio.auth.usuarios.ports.input.InicializarAdministradorUseCase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

/**
 * HU08 CA13: procedimiento controlado para crear el primer administrador. Solo existe con el
 * perfil "bootstrap-admin" (sin servidor web). La contraseña se lee de un archivo, no de los
 * argumentos del proceso ni de variables de entorno, y nunca se registra. Si ya existe un
 * administrador, termina con error sin cambiar nada.
 */
@Component
@Profile("bootstrap-admin")
public class InicializacionAdministradorRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(InicializacionAdministradorRunner.class);

    private final InicializarAdministradorUseCase inicializarAdministradorUseCase;
    private final String correo;
    private final String archivoContrasena;

    public InicializacionAdministradorRunner(InicializarAdministradorUseCase inicializarAdministradorUseCase,
            @Value("${auth.bootstrap.correo:}") String correo,
            @Value("${auth.bootstrap.archivo-contrasena:}") String archivoContrasena) {
        this.inicializarAdministradorUseCase = inicializarAdministradorUseCase;
        this.correo = correo;
        this.archivoContrasena = archivoContrasena;
    }

    @Override
    public void run(ApplicationArguments args) throws IOException {
        if (correo.isBlank() || archivoContrasena.isBlank()) {
            throw new IllegalStateException("Deben definirse AUTH_BOOTSTRAP_ADMIN_CORREO y "
                    + "AUTH_BOOTSTRAP_ADMIN_CONTRASENA_ARCHIVO");
        }
        String contrasena = leerContrasena(Path.of(archivoContrasena));
        UUID idAdministrador = inicializarAdministradorUseCase.inicializar(correo, contrasena);
        log.info("Administrador inicial creado mediante el procedimiento de inicialización; idUsuario={}",
                idAdministrador);
    }

    /** Se elimina la marca UTF-8 inicial y solo el salto de línea final que suelen dejar los editores. */
    static String leerContrasena(Path archivo) throws IOException {
        String contenido = Files.readString(archivo, StandardCharsets.UTF_8);
        if (contenido.startsWith("\uFEFF")) {
            contenido = contenido.substring(1);
        }
        if (contenido.endsWith("\r\n")) {
            return contenido.substring(0, contenido.length() - 2);
        }
        if (contenido.endsWith("\n")) {
            return contenido.substring(0, contenido.length() - 1);
        }
        return contenido;
    }
}
