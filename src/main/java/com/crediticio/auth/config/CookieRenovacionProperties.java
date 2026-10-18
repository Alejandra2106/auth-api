package com.crediticio.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("auth.cookie")
public record CookieRenovacionProperties(String nombre, String ruta, boolean secure, String sameSite) {
}
