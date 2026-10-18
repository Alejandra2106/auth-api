package com.crediticio.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

import java.time.Duration;
import java.util.List;

/**
 * Parámetros del JWT de acceso, configurados por ambiente. Las claves son ubicaciones de archivos
 * PEM externos (p. ej. file:/ruta/clave.pem); su contenido nunca se incluye en el repositorio.
 */
@ConfigurationProperties("auth.jwt")
public record JwtProperties(
        String emisor,
        List<String> audiencias,
        String audienciaPropia,
        String idClave,
        Resource clavePrivada,
        Resource clavePublica,
        Duration duracionAcceso) {
}
