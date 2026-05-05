package com.rishuxd.plugin.utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Utility class for password security.
 *
 * Storage pipeline:
 *   plaintext → SHA-256 hash → AES-256 encryption → Base64 string (stored in players.yml)
 *
 * Verification pipeline:
 *   plaintext → SHA-256 hash → AES-256 encryption → compare with stored value
 *
 * The AES key is derived from a plugin-specific passphrase using PBKDF2WithHmacSHA256,
 * so the stored ciphertext cannot be reversed without the key material.
 */
public final class PasswordUtil {

    private static final Logger LOGGER = Logger.getLogger("AuthPlugin");

    // ── AES configuration ────────────────────────────────────────────────────

    /** Passphrase used to derive the AES key. Change before deploying! */
    private static final String AES_PASSPHRASE = "AuthPlugin-RishuXD-SecretKey-2026";

    /** Static salt for PBKDF2 key derivation (16 bytes, hex-encoded). */
    private static final byte[] AES_SALT = "RishuXDPluginSalt".substring(0, 16)
            .getBytes(StandardCharsets.UTF_8);

    /** Fixed IV for deterministic encryption (allows equality comparison). */
    private static final byte[] AES_IV = "RishuXDAuthIV128".substring(0, 16)
            .getBytes(StandardCharsets.UTF_8);

    private static final String CIPHER_ALGO     = "AES/CBC/PKCS5Padding";
    private static final String KEY_ALGO        = "PBKDF2WithHmacSHA256";
    private static final int    KEY_ITERATIONS  = 65_536;
    private static final int    KEY_LENGTH      = 256; // bits

    // ── Derived key (computed once) ──────────────────────────────────────────

    private static final SecretKeySpec SECRET_KEY = deriveKey();

    private PasswordUtil() { /* utility class — no instances */ }

    // ─────────────────────────────────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Produces a hex-encoded SHA-256 hash of the given plaintext.
     *
     * @param password the plaintext password
     * @return 64-character lowercase hex string, or empty string on failure
     */
    public static String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.log(Level.SEVERE, "SHA-256 not available!", e);
            return "";
        }
    }

    /**
     * AES-256-CBC encrypts the given plaintext and returns a Base64-encoded ciphertext.
     * Uses a deterministic IV so that the same input always produces the same output,
     * enabling stored-value comparison without decryption.
     *
     * @param plaintext the value to encrypt (typically a SHA-256 hex hash)
     * @return Base64-encoded ciphertext, or empty string on failure
     */
    public static String encryptAES(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, new IvParameterSpec(AES_IV));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "AES encryption failed!", e);
            return "";
        }
    }

    /**
     * Decrypts an AES-256-CBC Base64-encoded ciphertext back to plaintext.
     * (Provided for completeness; verification uses re-encryption, not decryption.)
     *
     * @param ciphertext the Base64-encoded ciphertext
     * @return the original plaintext, or empty string on failure
     */
    public static String decryptAES(String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
            cipher.init(Cipher.DECRYPT_MODE, SECRET_KEY, new IvParameterSpec(AES_IV));
            byte[] decoded = Base64.getDecoder().decode(ciphertext);
            return new String(cipher.doFinal(decoded), StandardCharsets.UTF_8);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "AES decryption failed!", e);
            return "";
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────────────────

    /** Derives a 256-bit AES key from the passphrase using PBKDF2. */
    private static SecretKeySpec deriveKey() {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_ALGO);
            KeySpec spec = new PBEKeySpec(
                    AES_PASSPHRASE.toCharArray(),
                    AES_SALT,
                    KEY_ITERATIONS,
                    KEY_LENGTH
            );
            SecretKey tmp = factory.generateSecret(spec);
            return new SecretKeySpec(tmp.getEncoded(), "AES");
        } catch (Exception e) {
            // Fallback: derive a key directly from SHA-256 of passphrase
            LOGGER.log(Level.WARNING, "PBKDF2 key derivation failed, falling back to SHA-256 key.", e);
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] keyBytes = digest.digest(AES_PASSPHRASE.getBytes(StandardCharsets.UTF_8));
                return new SecretKeySpec(keyBytes, "AES");
            } catch (NoSuchAlgorithmException ex) {
                throw new RuntimeException("Cannot derive AES key — SHA-256 unavailable", ex);
            }
        }
    }

    /** Converts a byte array to a lowercase hex string. */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
