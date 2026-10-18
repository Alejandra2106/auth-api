package com.crediticio.auth.shared.exception;

import com.crediticio.auth.shared.response.ApiError;
import com.crediticio.auth.usuarios.domain.ActorRequeridoException;
import com.crediticio.auth.usuarios.domain.CorreoDuplicadoException;
import com.crediticio.auth.usuarios.domain.UsuarioInvalidoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> manejarValidacion(MethodArgumentNotValidException ex) {
        List<String> detalles = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .toList();
        return responder(HttpStatus.BAD_REQUEST, ApiError.de("VALIDATION_ERROR",
                "Los datos enviados no son válidos", detalles));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> manejarCuerpoInvalido(HttpMessageNotReadableException ex) {
        return responder(HttpStatus.BAD_REQUEST, ApiError.de("VALIDATION_ERROR",
                "El cuerpo de la solicitud no es válido"));
    }

    @ExceptionHandler(UsuarioInvalidoException.class)
    public ResponseEntity<ApiError> manejarUsuarioInvalido(UsuarioInvalidoException ex) {
        return responder(HttpStatus.BAD_REQUEST, ApiError.de("VALIDATION_ERROR", ex.getMessage()));
    }

    @ExceptionHandler(CorreoDuplicadoException.class)
    public ResponseEntity<ApiError> manejarCorreoDuplicado(CorreoDuplicadoException ex) {
        return responder(HttpStatus.CONFLICT, ApiError.de("CORREO_DUPLICADO", ex.getMessage()));
    }

    @ExceptionHandler(ActorRequeridoException.class)
    public ResponseEntity<ApiError> manejarActorRequerido(ActorRequeridoException ex) {
        return responder(HttpStatus.UNAUTHORIZED, ApiError.de("NO_AUTENTICADO", "Se requiere autenticación"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> manejarErrorInesperado(Exception ex) {
        // solo el tipo: el mensaje podría contener datos sensibles
        log.error("Error interno no controlado: {}", ex.getClass().getName());
        return responder(HttpStatus.INTERNAL_SERVER_ERROR, ApiError.de("INTERNAL_ERROR",
                "Ocurrió un error interno"));
    }

    private static ResponseEntity<ApiError> responder(HttpStatus estado, ApiError error) {
        return ResponseEntity.status(estado).body(error);
    }
}
