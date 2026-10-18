package com.crediticio.auth.support;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Par de claves RSA generado en tiempo de ejecución para las pruebas. Ninguna clave privada se
 * guarda en el repositorio: los PEM se escriben en directorios temporales del sistema.
 */
public final class ClavesRsaPrueba {

    private ClavesRsaPrueba() {
    }

    public static KeyPair generar() {
        try {
            KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
            generador.initialize(2048);
            return generador.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /** Escribe clave-privada.pem (PKCS#8) y clave-publica.pem (X.509) en el directorio indicado. */
    public static void escribirPem(KeyPair par, Path directorio) {
        try {
            Files.writeString(directorio.resolve("clave-privada.pem"),
                    pem("PRIVATE KEY", par.getPrivate().getEncoded()), StandardCharsets.US_ASCII);
            Files.writeString(directorio.resolve("clave-publica.pem"),
                    pem("PUBLIC KEY", par.getPublic().getEncoded()), StandardCharsets.US_ASCII);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    private static String pem(String tipo, byte[] contenido) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(contenido);
        return "-----BEGIN " + tipo + "-----\n" + base64 + "\n-----END " + tipo + "-----\n";
    }
}
