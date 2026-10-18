package com.crediticio.auth.usuarios.infrastructure.input;

import com.crediticio.auth.usuarios.ports.input.RestablecerContrasenaAdministradorUseCase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Path;

@Component
@Profile("reset-admin")
public class RestablecimientoAdministradorRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(RestablecimientoAdministradorRunner.class);

    private final RestablecerContrasenaAdministradorUseCase restablecerContrasenaAdministradorUseCase;
    private final String correo;
    private final String archivoContrasena;

    public RestablecimientoAdministradorRunner(
            RestablecerContrasenaAdministradorUseCase restablecerContrasenaAdministradorUseCase,
            @Value("${auth.reset.correo:}") String correo,
            @Value("${auth.reset.archivo-contrasena:}") String archivoContrasena) {
        this.restablecerContrasenaAdministradorUseCase = restablecerContrasenaAdministradorUseCase;
        this.correo = correo;
        this.archivoContrasena = archivoContrasena;
    }

    @Override
    public void run(ApplicationArguments args) throws IOException {
        if (correo.isBlank() || archivoContrasena.isBlank()) {
            throw new IllegalStateException("Deben definirse AUTH_ADMIN_RESET_CORREO y "
                    + "AUTH_ADMIN_RESET_CONTRASENA_ARCHIVO");
        }
        String contrasena = InicializacionAdministradorRunner.leerContrasena(Path.of(archivoContrasena));
        restablecerContrasenaAdministradorUseCase.restablecer(correo, contrasena);
        log.info("Contraseña del administrador restablecida; el hash se generó con la configuración actual.");
    }
}
