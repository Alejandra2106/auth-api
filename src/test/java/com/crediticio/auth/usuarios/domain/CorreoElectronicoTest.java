package com.crediticio.auth.usuarios.domain;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CorreoElectronicoTest {

    @Test
    void debeEliminarEspaciosExterioresYConvertirAMinusculas() {
        assertThat(CorreoElectronico.de("  Ana.Perez@Ejemplo.COM \t").valor()).isEqualTo("ana.perez@ejemplo.com");
    }

    @Test
    void dosCorreosQueSoloDifierenEnMayusculasDebenSerIguales() {
        assertThat(CorreoElectronico.de("ANA@ejemplo.com")).isEqualTo(CorreoElectronico.de("ana@EJEMPLO.com"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    void debeRechazarCorreoAusente(String correo) {
        assertThatThrownBy(() -> CorreoElectronico.de(correo)).isInstanceOf(UsuarioInvalidoException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"sin-arroba.com", "ana@", "@ejemplo.com", "ana@ejemplo", "ana @ejemplo.com",
            "ana@ejemplo..com", ".ana@ejemplo.com", "ana@-ejemplo.com"})
    void debeRechazarFormatosInvalidos(String correo) {
        assertThatThrownBy(() -> CorreoElectronico.de(correo))
                .isInstanceOf(UsuarioInvalidoException.class)
                .hasMessage("correo no tiene un formato válido");
    }

    @Test
    void debeRechazarCorreosDeMasDe254Caracteres() {
        String correo = "a".repeat(64) + "@" + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(61) + ".co";
        assertThatThrownBy(() -> CorreoElectronico.de(correo)).isInstanceOf(UsuarioInvalidoException.class);
    }

    @Test
    void elConstructorDebeExigirUnValorYaNormalizado() {
        assertThatThrownBy(() -> new CorreoElectronico("Ana@ejemplo.com"))
                .isInstanceOf(UsuarioInvalidoException.class)
                .hasMessage("correo debe estar normalizado");
    }
}
