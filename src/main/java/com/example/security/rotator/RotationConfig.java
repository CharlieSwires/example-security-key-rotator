package com.example.security.rotator;

import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

public final class RotationConfig implements AutoCloseable {
    private final char[] mongoUri;
    private final String database;
    private final char[] oldPassphrase;
    private final String oldSaltBase64;
    private final char[] newPassphrase;
    private final String newSaltBase64;
    private final int batchSize;
    private final boolean resume;

    public RotationConfig(char[] mongoUri, String database, char[] oldPassphrase,
                          String oldSaltBase64, char[] newPassphrase,
                          String newSaltBase64, int batchSize, boolean resume) {
        this.mongoUri = copyRequired(mongoUri, "MongoDB URI");
        this.database = requireText(database, "Database name");
        this.oldPassphrase = copyRequired(oldPassphrase, "Old passphrase");
        this.oldSaltBase64 = requireText(oldSaltBase64, "Old master salt");
        this.newPassphrase = copyRequired(newPassphrase, "New passphrase");
        this.newSaltBase64 = requireText(newSaltBase64, "New master salt");
        if (batchSize < 1 || batchSize > 1_000) {
            throw new IllegalArgumentException("Batch size must be between 1 and 1000");
        }
        this.batchSize = batchSize;
        this.resume = resume;

        FieldCrypto.validateSalt(this.oldSaltBase64, 16, "Old master salt");
        FieldCrypto.validateSalt(this.newSaltBase64, 32, "New master salt");
        if (FieldCrypto.fingerprint(this.oldPassphrase, this.oldSaltBase64)
                .equals(FieldCrypto.fingerprint(this.newPassphrase, this.newSaltBase64))) {
            throw new IllegalArgumentException("The old and new key/salt pairs must be different");
        }
    }

    public static RotationConfig fromEnvironment(Map<String, String> env) {
        return new RotationConfig(
                chars(env.get("MONGODB_URI")),
                env.getOrDefault("ROTATOR_DATABASE", "example_security"),
                chars(env.get("OLD_FIELD_CRYPTO_PASSPHRASE")),
                env.get("OLD_FIELD_CRYPTO_MASTER_SALT_B64"),
                chars(env.get("NEW_FIELD_CRYPTO_PASSPHRASE")),
                env.get("NEW_FIELD_CRYPTO_MASTER_SALT_B64"),
                parseBatchSize(env.getOrDefault("ROTATOR_BATCH_SIZE", "100")),
                Boolean.parseBoolean(env.getOrDefault("ROTATION_RESUME", "false"))
        );
    }

    private static int parseBatchSize(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("ROTATOR_BATCH_SIZE must be a number", ex);
        }
    }

    private static char[] chars(String value) {
        return value == null ? null : value.toCharArray();
    }

    private static char[] copyRequired(char[] value, String name) {
        if (value == null || value.length == 0 || isBlank(value)) {
            throw new IllegalArgumentException(name + " is required");
        }
        return Arrays.copyOf(value, value.length);
    }

    private static boolean isBlank(char[] value) {
        for (char character : value) {
            if (!Character.isWhitespace(character)) return false;
        }
        return true;
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
        return value.trim();
    }

    public String mongoUri() { return new String(mongoUri); }
    public String database() { return database; }
    public char[] oldPassphrase() { return Arrays.copyOf(oldPassphrase, oldPassphrase.length); }
    public String oldSaltBase64() { return oldSaltBase64; }
    public char[] newPassphrase() { return Arrays.copyOf(newPassphrase, newPassphrase.length); }
    public String newSaltBase64() { return newSaltBase64; }
    public int batchSize() { return batchSize; }
    public boolean resume() { return resume; }

    @Override
    public void close() {
        Arrays.fill(mongoUri, '\0');
        Arrays.fill(oldPassphrase, '\0');
        Arrays.fill(newPassphrase, '\0');
    }

    public static String generateSaltBase64() {
        byte[] bytes = new byte[32];
        new java.security.SecureRandom().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }
}
