package com.crediticio.auth.usuarios.domain;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Correo normalizado (HU08 CA02): sin espacios exteriores y en minúsculas. La unicidad se aplica
 * sobre este valor, de modo que dos correos que solo difieren en mayúsculas son el mismo (CA03).
 */
public record CorreoElectronico(String valor) {

    private static final int LONGITUD_MAXIMA = 254;
    private static final Pattern FORMATO = Pattern.compile(
            "^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
                    + "@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$");

    public CorreoElectronico {
        if (valor == null || valor.isEmpty()) {
            throw new UsuarioInvalidoException("correo es obligatorio");
        }
        if (!valor.equals(normalizar(valor))) {
            throw new UsuarioInvalidoException("correo debe estar normalizado");
        }
        if (valor.length() > LONGITUD_MAXIMA) {
            throw new UsuarioInvalidoException("correo no puede superar " + LONGITUD_MAXIMA + " caracteres");
        }
        if (!FORMATO.matcher(valor).matches()) {
            throw new UsuarioInvalidoException("correo no tiene un formato válido");
        }
    }

    public static CorreoElectronico de(String correo) {
        if (correo == null) {
            throw new UsuarioInvalidoException("correo es obligatorio");
        }
        return new CorreoElectronico(normalizar(correo));
    }

    private static String normalizar(String correo) {
        return correo.strip().toLowerCase(Locale.ROOT);
    }
}
