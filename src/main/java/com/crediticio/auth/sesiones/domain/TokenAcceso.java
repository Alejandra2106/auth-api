package com.crediticio.auth.sesiones.domain;

public record TokenAcceso(String valor, long expiraEnSegundos) {

    @Override
    public String toString() {
        return "TokenAcceso[expiraEnSegundos=" + expiraEnSegundos + "]";
    }
}
