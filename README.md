# MongoDB Encryption Key & Salt Rotator — Filesystem Schema Driven

This is an **offline maintenance utility** for rotating the passphrase and master salt used by the `FieldCrypto` AES-256-GCM format (`enc:v1:`).

## The important design rule

The rotator contains **no project-name, package-name, collection-name, model-class-name or application-field-name knowledge**.

You select the Java directory that contains your Spring Data MongoDB model classes, for example:

```text
C:\Users\charlie\eclipse-workspace\example-security\backend\src\main\java\com\example\security\model
```

The project could just as well be called `hospital-system`, `accounts`, or anything else. The package can also be anything.

The one deliberate convention is:

> **A String MongoDB model field whose Java name or `@Field` MongoDB name ends in `Encrypted` is treated as encrypted data.**

That convention is the contract between the application and this utility.

## What the scanner discovers

Starting at the selected model source directory, it recursively scans `.java` files and discovers:

- Spring Data `@Document` classes and their MongoDB collection names;
- `String` fields ending in `Encrypted`;
- `@Field("...")` names where present;
- embedded model objects;
- embedded arrays/lists such as `notes[].prescriptionEncrypted`;
- sibling `FooLookupHash` fields for a discovered `FooEncrypted` field.

Example:

```java
@Document(collection = "patient_appointment_documents")
class Appointment {
    private String patientDisplayNameEncrypted;
    private String patientDisplayNameLookupHash;
    private List<PatientClinicalNote> notes;
}

class PatientClinicalNote {
    private String subjectEncrypted;
    private String noteTextEncrypted;
    private String prescriptionEncrypted;
}
```

is discovered as:

```text
patient_appointment_documents ->
  patientDisplayNameEncrypted
  notes[].subjectEncrypted
  notes[].noteTextEncrypted
  notes[].prescriptionEncrypted
```

No copy of those names is hard-coded into the rotation engine.

## Null behaviour

A missing, `null`, or blank discovered encrypted value is **not decrypted and is not encrypted**:

```java
if (stored == null || stored.isBlank()) {
    // count it as empty and leave it alone
}
```

The utility never invents an encrypted value merely because the Java model contains an `*Encrypted` field.

## Safety check against stale source

Before a dry run or rotation, the utility also recursively checks MongoDB documents for properties ending in `Encrypted`.

If MongoDB contains an `*Encrypted` path that is **not present in the selected Java model source**, the operation stops. This matters because otherwise an old encrypted value could be left behind using the old key while you retire that key.

## Lookup hashes

When a model contains sibling fields such as:

```java
private String displayNameEncrypted;
private String displayNameLookupHash;
```

the lookup hash is automatically regenerated with the new key/salt-derived HMAC after the encrypted value is rotated. The rotator discovers this pairing by naming convention; it does not know application-specific field names.

## GUI

Build:

```bash
mvn clean package
```

Run:

```bash
java -jar target/example-security-key-rotator.jar
```

The first field is **MongoDB model source directory**. Select the Java folder containing the `@Document` model classes themselves, not the project root.

Then provide:

- MongoDB connection URL;
- database name;
- old passphrase and old Base64 master salt;
- new passphrase and new Base64 master salt;
- batch size.

Use **Dry-run check** before rotating. For an actual rotation the GUI requires confirmation that a verified backup exists and that all application backends using the database are stopped/drained.

## CLI

Set:

```text
ROTATOR_MODEL_SOURCE_DIR=<path to Java MongoDB model source directory>
MONGODB_URI=<MongoDB URI>
ROTATOR_DATABASE=<database name>
OLD_FIELD_CRYPTO_PASSPHRASE=<old passphrase>
OLD_FIELD_CRYPTO_MASTER_SALT_B64=<old salt>
NEW_FIELD_CRYPTO_PASSPHRASE=<new passphrase>
NEW_FIELD_CRYPTO_MASTER_SALT_B64=<new salt>
ROTATOR_BATCH_SIZE=100
ROTATOR_MODE=check
```

For a write rotation use `ROTATOR_MODE=rotate` and also set:

```text
APP_MAINTENANCE_CONFIRMED=true
BACKUP_CONFIRMED=true
ROTATION_CONFIRM=ROTATE
```

## Scope

The selected Java model source is read-only. The tool never modifies application source code. The only write target during `rotate` is the selected MongoDB database plus the utility's rotation journal/lock collections.

## Dry-run decryption diagnostics

If a discovered `*Encrypted` value cannot be authenticated, the dry run remains read-only and stops safely. The GUI now reports the MongoDB collection, document `_id`, and exact field path (including nested array indexes) rather than exposing only the low-level JCE `Tag mismatch` text.

A message saying that ciphertext matches neither the OLD nor NEW key/salt means AES-GCM authentication failed with both supplied secret sets. This is normally caused by an incorrect old passphrase/salt, a value written with another historical key/salt, or damaged ciphertext. Null and blank encrypted values continue to be skipped without decryption.

14 Random Word Generator
========================

How to Compile
==============

<p>cd ~/eclipse-workspace/example-security-key-rotator/src/main/java/com/example/security/random/words/util</p>
<p>javac *.java</p>
<p>./get-words.sh</p>

How to Run
==========

<p>cd ~/eclipse-workspace/example-security-key-rotator</p>
<p>java -cp src/main/java com.example.security.random.words.util.RandomPassphraseGenerator</p>
