package com.crediticio.auth.sesiones.ports.output;

public interface TokenRenovacionCriptografiaPort {

    /** Valor aleatorio criptográficamente seguro, apto para cookie. */
    String generar();

    /** Hash determinista con el que se guarda y se busca el token (nunca el valor en claro). */
    String hashear(String token);
}
