package com.crediticio.auth.sesiones.infrastructure.input;

import com.crediticio.auth.sesiones.application.dto.IniciarSesionRequest;
import com.crediticio.auth.sesiones.application.dto.TokenAccesoResponse;
import com.crediticio.auth.sesiones.domain.SesionEmitida;
import com.crediticio.auth.sesiones.ports.input.CerrarSesionUseCase;
import com.crediticio.auth.sesiones.ports.input.IniciarSesionUseCase;
import com.crediticio.auth.sesiones.ports.input.RenovarSesionUseCase;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.WebUtils;

@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Sesiones", description = "Inicio, renovación y cierre de sesión (HU09)")
public class SesionController {

    private final IniciarSesionUseCase iniciarSesionUseCase;
    private final RenovarSesionUseCase renovarSesionUseCase;
    private final CerrarSesionUseCase cerrarSesionUseCase;
    private final CookieRenovacion cookieRenovacion;
    private final ValidadorOrigen validadorOrigen;

    public SesionController(IniciarSesionUseCase iniciarSesionUseCase, RenovarSesionUseCase renovarSesionUseCase,
            CerrarSesionUseCase cerrarSesionUseCase, CookieRenovacion cookieRenovacion,
            ValidadorOrigen validadorOrigen) {
        this.iniciarSesionUseCase = iniciarSesionUseCase;
        this.renovarSesionUseCase = renovarSesionUseCase;
        this.cerrarSesionUseCase = cerrarSesionUseCase;
        this.cookieRenovacion = cookieRenovacion;
        this.validadorOrigen = validadorOrigen;
    }

    @PostMapping("/login")
    @Operation(summary = "Iniciar sesión", description = "Devuelve el JWT de acceso (15 min) y fija la cookie "
            + "HttpOnly del token de renovación. 401 genérico ante cualquier credencial inválida.")
    public ResponseEntity<TokenAccesoResponse> iniciar(@Valid @RequestBody IniciarSesionRequest request) {
        return responderConSesion(iniciarSesionUseCase.iniciar(request.correo(), request.contrasena()));
    }

    @PostMapping("/refresh")
    @Operation(summary = "Renovar la sesión", description = "Rota el token de renovación de la cookie. "
            + "Exige un Origin permitido.")
    public ResponseEntity<TokenAccesoResponse> renovar(HttpServletRequest request) {
        validadorOrigen.validar(request);
        return responderConSesion(renovarSesionUseCase.renovar(leerCookie(request)));
    }

    @PostMapping("/logout")
    @Operation(summary = "Cerrar sesión", description = "Revoca la sesión de renovación y elimina la cookie. "
            + "Exige un Origin permitido.")
    public ResponseEntity<Void> cerrar(HttpServletRequest request) {
        validadorOrigen.validar(request);
        cerrarSesionUseCase.cerrar(leerCookie(request));
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, cookieRenovacion.eliminar().toString())
                .build();
    }

    private ResponseEntity<TokenAccesoResponse> responderConSesion(SesionEmitida sesion) {
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,
                        cookieRenovacion.crear(sesion.tokenRenovacion(), sesion.vigenciaRenovacion()).toString())
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(TokenAccesoResponse.de(sesion.tokenAcceso()));
    }

    private String leerCookie(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, cookieRenovacion.nombre());
        return cookie == null ? null : cookie.getValue();
    }
}
