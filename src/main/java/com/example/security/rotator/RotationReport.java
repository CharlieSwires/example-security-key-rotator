package com.example.security.rotator;

import java.time.Duration;

public record RotationReport(
        String mode,
        long documents,
        long notes,
        long oldKeyFields,
        long newKeyFields,
        long plaintextFields,
        long nullFields,
        long fieldsWritten,
        long errors,
        Duration elapsed
) {
    public String summary() {
        return "Mode: " + mode + System.lineSeparator()
                + "Documents: " + documents + System.lineSeparator()
                + "Clinical notes: " + notes + System.lineSeparator()
                + "Fields using old key: " + oldKeyFields + System.lineSeparator()
                + "Fields already using new key: " + newKeyFields + System.lineSeparator()
                + "Legacy plaintext fields: " + plaintextFields + System.lineSeparator()
                + "Empty fields: " + nullFields + System.lineSeparator()
                + "Fields written: " + fieldsWritten + System.lineSeparator()
                + "Errors: " + errors + System.lineSeparator()
                + "Elapsed: " + elapsed.toSeconds() + " seconds";
    }

    static final class Mutable {
        long documents;
        long notes;
        long oldKeyFields;
        long newKeyFields;
        long plaintextFields;
        long nullFields;
        long fieldsWritten;
        long errors;

        RotationReport snapshot(String mode, Duration elapsed) {
            return new RotationReport(mode, documents, notes, oldKeyFields, newKeyFields,
                    plaintextFields, nullFields, fieldsWritten, errors, elapsed);
        }
    }
}
