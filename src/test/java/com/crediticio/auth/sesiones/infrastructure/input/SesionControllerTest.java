package com.crediticio.auth.sesiones.infrastructure.input;

import com.crediticio.auth.config.SecurityConfig;
import com.crediticio.auth.sesiones.domain.CredencialesInvalidasException;
import com.crediticio.auth.sesiones.domain.SesionEmitida;
import com.crediticio.auth.sesiones.domain.SesionInvalidaException;
import com.crediticio.auth.sesiones.domain.TokenAcceso;
import com.crediticio.auth.sesiones.ports.input.CerrarSesionUseCase;
import com.crediticio.auth.sesiones.ports.input.IniciarSesionUseCase;
import com.crediticio.auth.sesiones.ports.input.RenovarSesionUseCase;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;

import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(SesionController.class)
@Import({SecurityConfig.class, CookieRenovacion.class, ValidadorOrigen.class})
class SesionControllerTest {

    private static final String ORIGEN_PERMITIDO = "http://localhost:3000";
    private static final SesionEmitida SESION = new SesionEmitida(new TokenAcceso("jwt-de-acceso", 900),
            "token-de-renovacion", Duration.ofDays(7));

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private IniciarSesionUseCase iniciarSesionUseCase;

    @MockitoBean
    private RenovarSesionUseCase renovarSesionUseCase;

    @MockitoBean
    private CerrarSesionUseCase cerrarSesionUseCase;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @Test
    void elInicioDeSesionDebeDevolverElJwtYEntregarLaRenovacionSoloEnUnaCookieProtegida() throws Exception {
        when(iniciarSesionUseCase.iniciar("ana@ejemplo.com", "contrasena-segura")).thenReturn(SESION);

        mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"correo": "ana@ejemplo.com", "contrasena": "contrasena-segura"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("jwt-de-acceso"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andExpect(content().string(not(containsString("token-de-renovacion"))))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(header().string("Set-Cookie", allOf(
                        containsString("refresh_token=token-de-renovacion"),
                        containsString("HttpOnly"),
                        containsString("Secure"),
                        containsString("SameSite=Strict"),
                        containsString("Path=/api/v1/auth"),
                        containsString("Max-Age=604800"))));
    }

    @Test
    void credencialesInvalidasDebenResponder401Generico() throws Exception {
        when(iniciarSesionUseCase.iniciar("ana@ejemplo.com", "incorrecta"))
                .thenThrow(new CredencialesInvalidasException());

        mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"correo": "ana@ejemplo.com", "contrasena": "incorrecta"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("CREDENCIALES_INVALIDAS"))
                .andExpect(jsonPath("$.message").value("Credenciales inválidas"))
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    @Test
    void elInicioDeSesionSinDatosDebeResponder400() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_ERROR"));

        verifyNoInteractions(iniciarSesionUseCase);
    }

    @Test
    void laRenovacionSinOrigenOConOrigenAjenoDebeRechazarseSinTocarLaSesion() throws Exception {
        mockMvc.perform(post("/api/v1/auth/refresh").cookie(new Cookie("refresh_token", "token-actual")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("ORIGEN_NO_PERMITIDO"));
        mockMvc.perform(post("/api/v1/auth/refresh").header("Origin", "https://sitio-malicioso.example")
                        .cookie(new Cookie("refresh_token", "token-actual")))
                .andExpect(status().isForbidden());

        verifyNoInteractions(renovarSesionUseCase);
    }

    @Test
    void laRenovacionDebeRotarLaCookie() throws Exception {
        when(renovarSesionUseCase.renovar("token-actual")).thenReturn(SESION);

        mockMvc.perform(post("/api/v1/auth/refresh").header("Origin", ORIGEN_PERMITIDO)
                        .cookie(new Cookie("refresh_token", "token-actual")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("jwt-de-acceso"))
                .andExpect(header().string("Set-Cookie", containsString("refresh_token=token-de-renovacion")));
    }

    @Test
    void unaRenovacionInvalidaDebeResponder401YEliminarLaCookie() throws Exception {
        when(renovarSesionUseCase.renovar("token-reutilizado")).thenThrow(new SesionInvalidaException());

        mockMvc.perform(post("/api/v1/auth/refresh").header("Origin", ORIGEN_PERMITIDO)
                        .cookie(new Cookie("refresh_token", "token-reutilizado")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("SESION_INVALIDA"))
                .andExpect(header().string("Set-Cookie", allOf(containsString("refresh_token="),
                        containsString("Max-Age=0"))));
    }

    @Test
    void elCierreDeSesionDebeRevocarYEliminarLaCookie() throws Exception {
        mockMvc.perform(post("/api/v1/auth/logout").header("Origin", ORIGEN_PERMITIDO)
                        .cookie(new Cookie("refresh_token", "token-actual")))
                .andExpect(status().isNoContent())
                .andExpect(header().string("Set-Cookie", containsString("Max-Age=0")));

        verify(cerrarSesionUseCase).cerrar("token-actual");
    }
}
