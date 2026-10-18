package com.crediticio.auth.usuarios.infrastructure.input;

import com.crediticio.auth.config.SecurityConfig;
import com.crediticio.auth.sesiones.infrastructure.input.CookieRenovacion;
import com.crediticio.auth.usuarios.application.dto.RegistrarUsuarioRequest;
import com.crediticio.auth.usuarios.application.dto.UsuarioResponse;
import com.crediticio.auth.usuarios.domain.CorreoDuplicadoException;
import com.crediticio.auth.usuarios.domain.Rol;
import com.crediticio.auth.usuarios.ports.input.RegistrarUsuarioUseCase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.time.Instant;
import java.util.UUID;

import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UsuarioController.class)
@Import({SecurityConfig.class, CookieRenovacion.class})
class UsuarioControllerTest {

    private static final String CUERPO_VALIDO = """
            {"correo": "Nuevo@Ejemplo.com", "contrasena": "contrasena-segura", "rol": "ANALISTA_CREDITO"}
            """;

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private RegistrarUsuarioUseCase registrarUsuarioUseCase;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    private static RequestPostProcessor conRol(String rol) {
        return jwt().jwt(token -> token.subject(UUID.randomUUID().toString()).claim("role", rol))
                .authorities(new SimpleGrantedAuthority("ROLE_" + rol));
    }

    @Test
    void sinTokenDebeResponder401ConElFormatoComun() throws Exception {
        mockMvc.perform(post("/api/v1/usuarios").contentType(MediaType.APPLICATION_JSON).content(CUERPO_VALIDO))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("NO_AUTENTICADO"))
                .andExpect(jsonPath("$.traceId").exists())
                .andExpect(header().exists("X-Trace-Id"));

        verifyNoInteractions(registrarUsuarioUseCase);
    }

    @Test
    void conUnTokenInvalidoOExpiradoDebeResponder401() throws Exception {
        when(jwtDecoder.decode("token-invalido")).thenThrow(new BadJwtException("expirado"));

        mockMvc.perform(post("/api/v1/usuarios").header("Authorization", "Bearer token-invalido")
                        .contentType(MediaType.APPLICATION_JSON).content(CUERPO_VALIDO))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("NO_AUTENTICADO"))
                .andExpect(content().string(not(containsString("expirado"))));

        verifyNoInteractions(registrarUsuarioUseCase);
    }

    @Test
    void unAnalistaNoDebePoderCrearUsuariosNiAdministradores() throws Exception {
        mockMvc.perform(post("/api/v1/usuarios").with(conRol("ANALISTA_CREDITO"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"correo": "otro@ejemplo.com", "contrasena": "contrasena-segura", "rol": "ADMINISTRADOR_RIESGO"}
                                """))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("ACCESO_DENEGADO"));

        verifyNoInteractions(registrarUsuarioUseCase);
    }

    @Test
    void unAdministradorDebeRegistrarYRecibirSoloIdCorreoRolYFecha() throws Exception {
        UUID idUsuario = UUID.randomUUID();
        when(registrarUsuarioUseCase.registrar(any(RegistrarUsuarioRequest.class))).thenReturn(new UsuarioResponse(
                idUsuario, "nuevo@ejemplo.com", Rol.ANALISTA_CREDITO, Instant.parse("2026-10-16T12:00:00Z")));

        mockMvc.perform(post("/api/v1/usuarios").with(conRol("ADMINISTRADOR_RIESGO"))
                        .contentType(MediaType.APPLICATION_JSON).content(CUERPO_VALIDO))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.idUsuario").value(idUsuario.toString()))
                .andExpect(jsonPath("$.correo").value("nuevo@ejemplo.com"))
                .andExpect(jsonPath("$.rol").value("ANALISTA_CREDITO"))
                .andExpect(jsonPath("$.fechaCreacion").exists())
                .andExpect(jsonPath("$.contrasena").doesNotExist())
                .andExpect(jsonPath("$.hashContrasena").doesNotExist())
                .andExpect(content().string(not(containsString("contrasena-segura"))));
    }

    @Test
    void datosInvalidosDebenResponder400() throws Exception {
        mockMvc.perform(post("/api/v1/usuarios").with(conRol("ADMINISTRADOR_RIESGO"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"correo": "", "contrasena": "contrasena-segura"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.details").isArray());

        verifyNoInteractions(registrarUsuarioUseCase);
    }

    @Test
    void unRolFueraDelCatalogoDebeResponder400() throws Exception {
        mockMvc.perform(post("/api/v1/usuarios").with(conRol("ADMINISTRADOR_RIESGO"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"correo": "otro@ejemplo.com", "contrasena": "contrasena-segura", "rol": "SUPERUSUARIO"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_ERROR"));

        verifyNoInteractions(registrarUsuarioUseCase);
    }

    @Test
    void unCorreoDuplicadoDebeResponder409() throws Exception {
        when(registrarUsuarioUseCase.registrar(any(RegistrarUsuarioRequest.class)))
                .thenThrow(new CorreoDuplicadoException());

        mockMvc.perform(post("/api/v1/usuarios").with(conRol("ADMINISTRADOR_RIESGO"))
                        .contentType(MediaType.APPLICATION_JSON).content(CUERPO_VALIDO))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.errorCode").value("CORREO_DUPLICADO"));
    }

    @Test
    void unaRutaNoMapeadaDebeDenegarseAunqueHayaToken() throws Exception {
        mockMvc.perform(post("/api/v1/otra-ruta").with(conRol("ADMINISTRADOR_RIESGO")))
                .andExpect(status().isForbidden());
    }
}
