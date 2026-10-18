package com.crediticio.auth.sesiones.infrastructure.input;

import com.crediticio.auth.config.WebProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

/**
 * Protección CSRF de los endpoints que actúan con la cookie de renovación. CORS no la sustituye:
 * un formulario de otro sitio puede enviar la cookie sin pasar por CORS. Los navegadores incluyen
 * Origin en toda petición POST, de modo que se exige y debe ser un origen permitido.
 */
@Component
public class ValidadorOrigen {

    private final WebProperties webProperties;

    public ValidadorOrigen(WebProperties webProperties) {
        this.webProperties = webProperties;
    }

    public void validar(HttpServletRequest request) {
        String origen = request.getHeader(HttpHeaders.ORIGIN);
        if (origen == null || !webProperties.origenesPermitidos().contains(origen)) {
            throw new OrigenNoPermitidoException();
        }
    }
}
