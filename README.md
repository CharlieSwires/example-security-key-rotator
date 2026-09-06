# ExampleSecurity Key Rotator — Filesystem Schema Checked

This is the **filesystem-schema** variant of the standalone Java 17 key/salt rotator.

The important difference from the ordinary rotator is that it **asks for the path to your actual `example-security` project before it will touch MongoDB**.

The selected directory must contain:

```text
example-security/
  backend/
    src/main/java/
```

The utility scans the Spring Data MongoDB model source beneath that directory, discovers the `@Document(collection=...)` collections and fields whose Java names end in `Encrypted`, including the encrypted fields in `PatientClinicalNote` as `notes[].…` paths.

The **filesystem-derived schema is authoritative**. The rotator only checks and rotates encrypted fields that actually exist in the selected `example-security` source tree. If an older field has disappeared from the application model (for example a former top-level `prescriptionEncrypted`), it is not required and it is not touched in MongoDB.

The program still has a deliberately small **supported-path safety bound**. If the filesystem scanner discovers a *new* encrypted field or encrypted collection that the rotation engine does not yet know how to process safely, dry-run and rotation are blocked until support is added. This avoids silently missing newly introduced encrypted data.

## What the program asks for

The Swing GUI asks for:

1. **ExampleSecurity project directory** — browse to the real `example-security` source folder.
2. MongoDB connection URL.
3. Database name (normally `example_security`).
4. Current field-encryption passphrase.
5. Current Base64 master salt.
6. New passphrase.
7. New Base64 master salt (or generate a new 32-byte salt).
8. Batch size.

Before any MongoDB operation it prints the filesystem schema it found. **Only those discovered encrypted paths are processed.** Null or blank stored values are skipped by the crypto classifier and are never decrypted.

## Build and run

Requires JDK 17+ and Maven 3.9+:

```bash
mvn clean test
mvn clean package
java -jar target/example-security-key-rotator.jar
```

On Windows you can also run `run-gui.bat` after building.

## Safety

Use **Dry-run check** first. For a real rotation, take and verify a backup and stop/drain every backend instance. The GUI requires both confirmations and requires you to type `ROTATE` before writes begin.

The filesystem scan is a safety gate; it does not modify your `example-security` source files. MongoDB remains the data being checked/rotated.

## Null values and removed fields

A database value that is `null` or blank is classified as `NULL`; the rotator does not attempt to decrypt it. During rotation the corresponding active encrypted field remains null.

This is different from a field that is absent from the application source schema. An absent source-schema field is not part of the active rotation plan at all: the rotator does not decrypt it, create it, overwrite it, or clear any associated legacy field.

For CLI mode, set `EXAMPLE_SECURITY_PROJECT_DIR` to the root of the real `example-security` project.
