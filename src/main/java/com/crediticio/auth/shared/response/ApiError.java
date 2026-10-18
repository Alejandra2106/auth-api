package com.crediticio.auth.shared.response;

import org.slf4j.MDC;

import java.util.List;

/**
 * Formato uniforme de error del contrato técnico común (errorCode, message, details, traceId).
 * Nunca incluye trazas de pila, contraseñas, hashes ni tokens.
 */
public record ApiError(String errorCode, String message, List<String> details, String traceId) {

    public static final String MDC_TRACE_ID = "traceId";

    public ApiError {
        details = details == null ? List.of() : List.copyOf(details);
    }

    public static ApiError de(String errorCode, String message) {
        return de(errorCode, message, List.of());
    }

    public static ApiError de(String errorCode, String message, List<String> details) {
        return new ApiError(errorCode, message, details, MDC.get(MDC_TRACE_ID));
    }
}
