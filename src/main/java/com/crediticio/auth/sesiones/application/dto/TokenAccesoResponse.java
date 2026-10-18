package com.crediticio.auth.sesiones.application.dto;

import com.crediticio.auth.sesiones.domain.TokenAcceso;

/** El token de renovación nunca viaja en el cuerpo; solo en la cookie HttpOnly (HU09 CA13). */
public record TokenAccesoResponse(String accessToken, String tokenType, long expiresIn) {

    public static TokenAccesoResponse de(TokenAcceso tokenAcceso) {
        return new TokenAccesoResponse(tokenAcceso.valor(), "Bearer", tokenAcceso.expiraEnSegundos());
    }

    @Override
    public String toString() {
        return "TokenAccesoResponse[tokenType=" + tokenType + ", expiresIn=" + expiresIn + "]";
    }
}
