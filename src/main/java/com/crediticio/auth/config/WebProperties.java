package com.crediticio.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/** Orígenes del frontend permitidos para CORS y para la validación de Origin. */
@ConfigurationProperties("auth.web")
public record WebProperties(List<String> origenesPermitidos) {

    public WebProperties {
        origenesPermitidos = origenesPermitidos == null ? List.of() : List.copyOf(origenesPermitidos);
    }
}
