# ExampleSecurity Key & Salt Rotator

Standalone Java 17 maintenance application for rotating the AES-GCM field
encryption passphrase and PBKDF2 master salt used by `example-security`.

It is intentionally a separate repository and has no Spring Boot web server.
The normal entry point is a Bootstrap-inspired Swing interface. A restricted
environment-variable-only CLI is also included for controlled automation.

## Safety properties

- Read-only dry-run checks every encrypted field before rotation.
- Old salt accepts the application's legacy 16-byte minimum; a new salt must be
  at least 32 random bytes.
- New salts can be generated in the Swing interface using `SecureRandom`.
- MongoDB is processed in `_id` order in bounded batches; `findAll()` is never
  used.
- A global record in `crypto_rotation_locks` blocks concurrent rotations, while
  a deterministic `crypto_rotation_records` journal prevents accidental repeats
  and records resumable progress.
- Interrupted runs are resumable: each value is authenticated against the old
  key and then the new key, so already-rotated values are not encrypted twice.
- A verification pass ensures no old-key or legacy plaintext encrypted fields
  remain before recording `COMPLETED`.
- TOTP secrets, lookup HMACs, office details, appointment fields and nested
  clinical-note fields are included.
- Legacy appointment/note plaintext fields are encrypted before being cleared.
- Passphrases and MongoDB credentials are never accepted as command-line
  arguments or written into the rotation journal.

## Build

Requirements:

- JDK 17 or newer
- Maven 3.9 or newer
- Network access to Maven Central for the first build

```bash
mvn clean test
mvn clean package
```

The runnable fat JAR is:

```text
target/example-security-key-rotator.jar
```

## Swing interface

```bash
java -jar target/example-security-key-rotator.jar
```

On Windows, double-click `run-gui.bat` after building, or run it from Command
Prompt. On Linux/macOS use `./run-gui.sh`.

The interface provides:

1. Masked MongoDB URL and old/new passphrase fields.
2. Old and new Base64 salt fields.
3. Cryptographically secure 32-byte salt generation.
4. MongoDB connection testing.
5. A read-only dry run.
6. Backup and maintenance-mode confirmations.
7. Progress and final verification results.
8. Explicit `ROTATE` confirmation before any writes.

Use the application database user only if it has `readWrite` access to the
three application collections and `crypto_rotation_records`. A dedicated,
temporary maintenance account is preferable. Do not use the read-only backup
user for rotation.

## Maintenance procedure

1. Take a MongoDB snapshot or `mongodump` and test that it can be read.
2. Put the public application into maintenance mode.
3. Stop or drain **every** backend replica.
4. Start this rotator from an allowlisted maintenance machine or private VPS
   network.
5. Enter the current and new values and select **Dry-run check**.
6. Resolve any reported field that cannot be authenticated.
7. Confirm the backup and application shutdown boxes.
8. Select **Rotate key and salt**, then type `ROTATE`.
9. Wait for the rotation and verification passes to complete.
10. Set both new values on every application server:

```text
FIELD_CRYPTO_PASSPHRASE=<new passphrase>
FIELD_CRYPTO_MASTER_SALT_B64=<new Base64 salt>
```

11. Start the backends, test login/MFA and decrypt representative records.
12. Return the load balancer to service.

Never run old-key and new-key backend instances simultaneously. Retain the old
key pair securely and offline for as long as any retained database backup still
requires it.

## Connection URLs

Atlas example:

```text
mongodb+srv://maintenance-user:PASSWORD@cluster.example.mongodb.net/example_security?retryWrites=true&w=majority
```

Krystal TLS/allowlist example:

```text
mongodb://maintenance-user:PASSWORD@app.example.co.uk:27017/example_security?authSource=example_security&authMechanism=SCRAM-SHA-256&directConnection=true&tls=true
```

For a MongoDB container with no published port, run the rotator inside a
temporary container on the data network or use an SSH tunnel. Do not make port
27017 publicly accessible.

## CLI mode

The CLI reads all sensitive values from environment variables. It does not
accept them after `--cli`, keeping them out of shell command history and process
arguments.

```text
MONGODB_URI
ROTATOR_DATABASE                         default: example_security
OLD_FIELD_CRYPTO_PASSPHRASE
OLD_FIELD_CRYPTO_MASTER_SALT_B64
NEW_FIELD_CRYPTO_PASSPHRASE
NEW_FIELD_CRYPTO_MASTER_SALT_B64
ROTATOR_BATCH_SIZE                       default: 100
ROTATOR_MODE                             check or rotate
ROTATION_RESUME                          true only after investigation
```

For `ROTATOR_MODE=rotate`, these three confirmations are additionally mandatory:

```text
APP_MAINTENANCE_CONFIRMED=true
BACKUP_CONFIRMED=true
ROTATION_CONFIRM=ROTATE
```

Then run:

```bash
java -jar target/example-security-key-rotator.jar --cli
```

Prefer a root-only environment file or secret manager. Do not commit secrets,
paste them into CI logs, or embed them in a script.

## Recovery from interruption

An interruption can leave earlier batches using the new key and later batches
using the old key. Keep both pairs available, investigate the cause, then select
the resume option using the exact same old and new pairs. The rotator recognises
both states and continues without double encryption.

Do not restart `example-security` while the database is mixed. If the failed
attempt cannot safely be resumed, restore the verified pre-rotation backup.

## If the database structure changes

The rotator deliberately uses an explicit schema map rather than recursively
rewriting every string beginning with `enc:v1:`. That avoids changing unrelated
collections or application metadata by accident.

As a fail-safe, the preflight detects an `enc:v1:` value at an unknown path in
any of the three mapped collections and refuses to rotate until the map is
updated. It will not silently leave that newly encrypted field on the old key.

- Adding or removing an ordinary plaintext field requires no rotator change.
- Adding an encrypted leaf field requires adding that leaf to both the scan and
  rotation mappings.
- Moving or renaming a collection, embedded object, or array requires changing
  the branch traversal and its encrypted leaves.
- Changing the ciphertext format, key derivation, lookup normalization, or
  encryption purpose requires a new compatibility implementation and tests.

The current mapping covers `users`, `offices`,
`patient_appointment_documents`, and the embedded clinical-note array as they
exist in the September 2026 ExampleSecurity source. Update and dry-run this tool
against a restored production backup whenever that persisted schema changes.
