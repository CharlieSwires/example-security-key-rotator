package com.example.security.rotator;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;

public final class FieldCrypto implements AutoCloseable {
    public static final String PREFIX = "enc:v1:";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int KEY_BITS = 256;
    private static final int ITERATIONS = 600_000;

    private final SecureRandom random = new SecureRandom();
    private final byte[] encryptionKey;
    private final byte[] lookupKey;

    public FieldCrypto(char[] passphrase, String saltBase64) {
        if (passphrase == null || passphrase.length == 0) {
            throw new IllegalArgumentException("Passphrase is required");
        }
        byte[] salt = validateSalt(saltBase64, 16, "Master salt");
        this.encryptionKey = derive(passphrase, salt, "field-encryption");
        this.lookupKey = derive(passphrase, salt, "field-lookup-hmac");
        Arrays.fill(salt, (byte) 0);
    }

    public String encrypt(String plaintext) {
        if (plaintext == null) return null;
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"),
                    new GCMParameterSpec(TAG_BITS, iv));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return PREFIX + Base64.getEncoder().encodeToString(iv) + ":"
                    + Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception ex) {
            throw new RotationException("Could not encrypt a field", ex);
        }
    }

    public String encryptBlankAsNull(String plaintext) {
        return plaintext == null || plaintext.isBlank() ? null : encrypt(plaintext.trim());
    }

    public String decrypt(String stored) {
        if (stored == null) return null;
        if (!stored.startsWith(PREFIX)) return stored;
        try {
            String[] parts = stored.substring(PREFIX.length()).split(":", 2);
            if (parts.length != 2) throw new IllegalArgumentException("Invalid encrypted-field payload");
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            if (iv.length != IV_BYTES) throw new IllegalArgumentException("Invalid AES-GCM IV length");
            byte[] encrypted = Base64.getDecoder().decode(parts[1]);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"),
                    new GCMParameterSpec(TAG_BITS, iv));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (AEADBadTagException ex) {
            throw new KeyMismatchException("Encrypted value does not match this key", ex);
        } catch (Exception ex) {
            throw new RotationException("Invalid or corrupt encrypted-field payload", ex);
        }
    }

    public String lookupHash(String plaintext) {
        if (plaintext == null || plaintext.isBlank()) return null;
        String normalized = plaintext.trim().replaceAll("\\s+", " ").toLowerCase(Locale.ROOT);
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(lookupKey, "HmacSHA256"));
            return "hmac:v1:" + Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(normalized.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new RotationException("Could not create lookup hash", ex);
        }
    }

    public static String fingerprint(char[] passphrase, String saltBase64) {
        if (passphrase == null || passphrase.length == 0) {
            throw new IllegalArgumentException("Passphrase is required");
        }
        validateSalt(saltBase64, 16, "Master salt");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update("field-crypto-passphrase-fingerprint-v1:".getBytes(StandardCharsets.UTF_8));
            digest.update(saltBase64.trim().getBytes(StandardCharsets.UTF_8));
            digest.update((byte) ':');
            digest.update(new String(passphrase).getBytes(StandardCharsets.UTF_8));
            return "sha256:" + HexFormat.of().formatHex(digest.digest());
        } catch (Exception ex) {
            throw new RotationException("Could not fingerprint key", ex);
        }
    }

    public static byte[] validateSalt(String value, int minimumBytes, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
        try {
            byte[] decoded = Base64.getDecoder().decode(value.trim());
            if (decoded.length < minimumBytes) {
                throw new IllegalArgumentException(name + " must decode to at least " + minimumBytes + " bytes");
            }
            return decoded;
        } catch (IllegalArgumentException ex) {
            if (ex.getMessage() != null && ex.getMessage().contains("must decode")) throw ex;
            throw new IllegalArgumentException(name + " must be valid Base64", ex);
        }
    }

    private static byte[] derive(char[] passphrase, byte[] salt, String purpose) {
        PBEKeySpec spec = null;
        try {
            byte[] purposeBytes = purpose.getBytes(StandardCharsets.UTF_8);
            byte[] purposeSalt = Arrays.copyOf(salt, salt.length + purposeBytes.length);
            System.arraycopy(purposeBytes, 0, purposeSalt, salt.length, purposeBytes.length);
            spec = new PBEKeySpec(passphrase, purposeSalt, ITERATIONS, KEY_BITS);
            byte[] result = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
            Arrays.fill(purposeSalt, (byte) 0);
            return result;
        } catch (Exception ex) {
            throw new RotationException("Could not derive encryption key", ex);
        } finally {
            if (spec != null) spec.clearPassword();
        }
    }

    @Override
    public void close() {
        Arrays.fill(encryptionKey, (byte) 0);
        Arrays.fill(lookupKey, (byte) 0);
    }

    public static class RotationException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public RotationException(String message, Throwable cause) { super(message, cause); }
        public RotationException(String message) { super(message); }
    }

    public static final class KeyMismatchException extends RotationException {
        private static final long serialVersionUID = 1L;

        public KeyMismatchException(String message, Throwable cause) { super(message, cause); }
    }
}
