package com.crediticio.auth.sesiones.ports.input;

public interface CerrarSesionUseCase {

    /** Idempotente: un token desconocido o ya revocado no produce error. */
    void cerrar(String tokenRenovacion);
}
