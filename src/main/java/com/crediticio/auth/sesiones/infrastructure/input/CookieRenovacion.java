package com.crediticio.auth.sesiones.infrastructure.input;

import com.crediticio.auth.config.CookieRenovacionProperties;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Cookie del token de renovación: HttpOnly (inaccesible para JavaScript), Secure según el ambiente,
 * SameSite configurable y limitada a la ruta /api/v1/auth para que no se envíe a otros endpoints.
 */
@Component
public class CookieRenovacion {

    private final CookieRenovacionProperties propiedades;

    public CookieRenovacion(CookieRenovacionProperties propiedades) {
        this.propiedades = propiedades;
    }

    public String nombre() {
        return propiedades.nombre();
    }

    public ResponseCookie crear(String tokenRenovacion, Duration vigencia) {
        return base(tokenRenovacion).maxAge(vigencia).build();
    }

    public ResponseCookie eliminar() {
        return base("").maxAge(Duration.ZERO).build();
    }

    private ResponseCookie.ResponseCookieBuilder base(String valor) {
        return ResponseCookie.from(propiedades.nombre(), valor)
                .httpOnly(true)
                .secure(propiedades.secure())
                .sameSite(propiedades.sameSite())
                .path(propiedades.ruta());
    }
}
