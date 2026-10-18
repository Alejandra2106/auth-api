package com.crediticio.auth.usuarios.domain;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PoliticaContrasenaTest {

    @Test
    void debeAceptarExactamenteDoceCaracteres() {
        assertThatCode(() -> PoliticaContrasena.validar("abcdefghijkl")).doesNotThrowAnyException();
    }

    @Test
    void debeRechazarOnceCaracteres() {
        assertThatThrownBy(() -> PoliticaContrasena.validar("abcdefghijk"))
                .isInstanceOf(UsuarioInvalidoException.class)
                .hasMessage("contrasena debe tener al menos 12 caracteres");
    }

    @Test
    void debeContarCaracteresYNoUnidadesUtf16() {
        // 11 emojis son 22 unidades UTF-16 pero solo 11 caracteres
        assertThatThrownBy(() -> PoliticaContrasena.validar("😀".repeat(11)))
                .isInstanceOf(UsuarioInvalidoException.class);
    }

    @Test
    void noDebeImponerUnMaximoQueHu08NoEstablece() {
        assertThatCode(() -> PoliticaContrasena.validar("a".repeat(500))).doesNotThrowAnyException();
        assertThatCode(() -> PoliticaContrasena.validar("ñ".repeat(200))).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @NullAndEmptySource
    void debeRechazarContrasenaAusente(String contrasena) {
        assertThatThrownBy(() -> PoliticaContrasena.validar(contrasena))
                .isInstanceOf(UsuarioInvalidoException.class)
                .hasMessage("contrasena es obligatoria");
    }
}
