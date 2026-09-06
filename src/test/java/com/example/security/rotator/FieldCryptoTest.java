package com.example.security.rotator;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FieldCryptoTest {
    private static final String OLD_SALT = Base64.getEncoder().encodeToString(new byte[32]);

    @Test
    void formatMatchesExampleSecurityAndRoundTrips() {
        try (FieldCrypto crypto = new FieldCrypto("fourteen suitable random words would go here".toCharArray(), OLD_SALT)) {
            String encrypted = crypto.encrypt("clinical value");
            assertTrue(encrypted.startsWith("enc:v1:"));
            assertEquals("clinical value", crypto.decrypt(encrypted));
        }
    }

    @Test
    void wrongKeyIsRejectedByGcmAuthentication() {
        try (FieldCrypto first = new FieldCrypto("first long passphrase".toCharArray(), OLD_SALT);
             FieldCrypto second = new FieldCrypto("second long passphrase".toCharArray(), OLD_SALT)) {
            String encrypted = first.encrypt("TOTP-SECRET");
            assertThrows(FieldCrypto.KeyMismatchException.class, () -> second.decrypt(encrypted));
        }
    }

    @Test
    void encryptionUsesANewIvForEveryValue() {
        try (FieldCrypto crypto = new FieldCrypto("long random passphrase".toCharArray(), OLD_SALT)) {
            assertNotEquals(crypto.encrypt("same"), crypto.encrypt("same"));
        }
    }

    @Test
    void newConfigurationRequires32ByteSalt() {
        String shortSalt = Base64.getEncoder().encodeToString(new byte[16]);
        assertThrows(IllegalArgumentException.class, () -> new RotationConfig(
                "mongodb://localhost/test".toCharArray(), "test",
                "old passphrase".toCharArray(), OLD_SALT,
                "new passphrase".toCharArray(), shortSalt, 100, false));
    }
}
