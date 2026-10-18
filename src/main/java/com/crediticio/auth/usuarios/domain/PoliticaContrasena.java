package com.crediticio.auth.usuarios.domain;

/**
 * HU08 CA04: mínimo 12 caracteres. HU08 no establece un máximo y el algoritmo de hash (PBKDF2)
 * no lo exige, por lo que no se impone ninguno ni se trunca la contraseña.
 */
public final class PoliticaContrasena {

    public static final int LONGITUD_MINIMA = 12;

    private PoliticaContrasena() {
    }

    public static void validar(String contrasena) {
        if (contrasena == null || contrasena.isEmpty()) {
            throw new UsuarioInvalidoException("contrasena es obligatoria");
        }
        if (contrasena.codePointCount(0, contrasena.length()) < LONGITUD_MINIMA) {
            throw new UsuarioInvalidoException("contrasena debe tener al menos " + LONGITUD_MINIMA + " caracteres");
        }
    }
}
