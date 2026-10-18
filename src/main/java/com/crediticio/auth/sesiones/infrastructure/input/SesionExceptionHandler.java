package com.crediticio.auth.sesiones.infrastructure.input;

import com.crediticio.auth.sesiones.domain.CredencialesInvalidasException;
import com.crediticio.auth.sesiones.domain.SesionInvalidaException;
import com.crediticio.auth.shared.response.ApiError;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Errores propios de las sesiones; los mensajes son genéricos y no revelan la causa (HU09 CA02, CA12). */
@RestControllerAdvice(assignableTypes = SesionController.class)
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SesionExceptionHandler {

    private final CookieRenovacion cookieRenovacion;

    public SesionExceptionHandler(CookieRenovacion cookieRenovacion) {
        this.cookieRenovacion = cookieRenovacion;
    }

    @ExceptionHandler(CredencialesInvalidasException.class)
    public ResponseEntity<ApiError> manejarCredencialesInvalidas(CredencialesInvalidasException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiError.de("CREDENCIALES_INVALIDAS", "Credenciales inválidas"));
    }

    @ExceptionHandler(SesionInvalidaException.class)
    public ResponseEntity<ApiError> manejarSesionInvalida(SesionInvalidaException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .header(HttpHeaders.SET_COOKIE, cookieRenovacion.eliminar().toString())
                .body(ApiError.de("SESION_INVALIDA", "La sesión no es válida"));
    }

    @ExceptionHandler(OrigenNoPermitidoException.class)
    public ResponseEntity<ApiError> manejarOrigenNoPermitido(OrigenNoPermitidoException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ApiError.de("ORIGEN_NO_PERMITIDO", "El origen de la solicitud no está permitido"));
    }
}
