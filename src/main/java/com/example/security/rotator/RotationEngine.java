package com.example.security.rotator;

import com.mongodb.MongoWriteException;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.BulkWriteOptions;
import com.mongodb.client.model.UpdateOneModel;
import com.mongodb.client.model.WriteModel;
import org.bson.Document;
import org.bson.conversions.Bson;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static com.mongodb.client.model.Filters.eq;
import static com.mongodb.client.model.Filters.gt;
import static com.mongodb.client.model.Sorts.ascending;
import static com.mongodb.client.model.Updates.combine;
import static com.mongodb.client.model.Updates.set;

public final class RotationEngine {
    private static final String USERS = "users";
    private static final String OFFICES = "offices";
    private static final String APPOINTMENTS = "patient_appointment_documents";
    private static final String RECORDS = "crypto_rotation_records";
    private static final String LOCKS = "crypto_rotation_locks";
    private static final String GLOBAL_LOCK_ID = "field-crypto-global";
    private static final Set<String> USER_ENCRYPTED_PATHS = Set.of(
            "displayNameEncrypted", "telephoneEncrypted", "totpSecretEncrypted");
    private static final Set<String> OFFICE_ENCRYPTED_PATHS = Set.of(
            "addressEncrypted", "telephoneEncrypted");
    private static final Set<String> APPOINTMENT_ENCRYPTED_PATHS = Set.of(
            "patientDisplayNameEncrypted", "patientTelephoneEncrypted", "clinicNameEncrypted",
            "clinicianEncrypted", "prescriptionEncrypted", "notes[].subjectEncrypted",
            "notes[].noteTextEncrypted", "notes[].prescriptionEncrypted");

    private final Map<String, Set<String>> activeEncryptedPaths;

    /**
     * Uses the encrypted paths discovered from the actual ExampleSecurity source tree.
     * A path that is not present in that filesystem-derived schema is never decrypted,
     * encrypted, created, or nulled in MongoDB.
     */
    public RotationEngine(Map<String, Set<String>> activeEncryptedPaths) {
        if (activeEncryptedPaths == null) throw new IllegalArgumentException("Filesystem schema is required");
        this.activeEncryptedPaths = activeEncryptedPaths.entrySet().stream()
                .collect(java.util.stream.Collectors.toUnmodifiableMap(
                        Map.Entry::getKey, e -> Set.copyOf(e.getValue())));
    }

    /**
     * Kept for compatibility with older callers. The filesystem-schema GUI and CLI do not
     * use this constructor; they always pass a scanned schema.
     */
    public RotationEngine() {
        this(Map.of(USERS, USER_ENCRYPTED_PATHS, OFFICES, OFFICE_ENCRYPTED_PATHS,
                APPOINTMENTS, APPOINTMENT_ENCRYPTED_PATHS));
    }

    private Set<String> active(String collection) {
        return activeEncryptedPaths.getOrDefault(collection, Set.of());
    }

    private boolean active(String collection, String path) {
        return active(collection).contains(path);
    }

    public void testConnection(RotationConfig config) {
        try (MongoClient client = MongoClients.create(config.mongoUri())) {
            client.getDatabase(config.database()).runCommand(new Document("ping", 1));
        }
    }

    public void testConnection(char[] mongoUri, String database) {
        if (mongoUri == null || mongoUri.length == 0) {
            throw new IllegalArgumentException("MongoDB URI is required");
        }
        if (database == null || database.isBlank()) {
            throw new IllegalArgumentException("Database name is required");
        }
        try (MongoClient client = MongoClients.create(new String(mongoUri))) {
            client.getDatabase(database.trim()).runCommand(new Document("ping", 1));
        }
    }

    public RotationReport check(RotationConfig config, ProgressListener progress) {
        Instant started = Instant.now();
        try (MongoClient client = MongoClients.create(config.mongoUri());
             FieldCrypto oldCrypto = new FieldCrypto(config.oldPassphrase(), config.oldSaltBase64());
             FieldCrypto newCrypto = new FieldCrypto(config.newPassphrase(), config.newSaltBase64())) {
            MongoDatabase database = client.getDatabase(config.database());
            database.runCommand(new Document("ping", 1));
            RotationReport.Mutable stats = scan(database, oldCrypto, newCrypto, config.batchSize(), progress);
            return stats.snapshot("CHECK", Duration.between(started, Instant.now()));
        }
    }

    public RotationReport rotate(RotationConfig config, ProgressListener progress) {
        Instant started = Instant.now();
        String fromFingerprint = FieldCrypto.fingerprint(config.oldPassphrase(), config.oldSaltBase64());
        String toFingerprint = FieldCrypto.fingerprint(config.newPassphrase(), config.newSaltBase64());
        String rotationId = "field-crypto:" + fromFingerprint + ":to:" + toFingerprint;

        try (MongoClient client = MongoClients.create(config.mongoUri());
             FieldCrypto oldCrypto = new FieldCrypto(config.oldPassphrase(), config.oldSaltBase64());
             FieldCrypto newCrypto = new FieldCrypto(config.newPassphrase(), config.newSaltBase64())) {
            MongoDatabase database = client.getDatabase(config.database());
            database.runCommand(new Document("ping", 1));

            progress.update("Preflight: verifying every encrypted field", 0);
            RotationReport.Mutable preflight = scan(database, oldCrypto, newCrypto,
                    config.batchSize(), progress);
            acquireLock(database, rotationId, fromFingerprint, toFingerprint, config.resume());

            RotationReport.Mutable written = new RotationReport.Mutable();
            try {
                rotateUsers(database, oldCrypto, newCrypto, config.batchSize(), written, progress);
                checkpoint(database, rotationId, "offices", written);
                rotateOffices(database, oldCrypto, newCrypto, config.batchSize(), written, progress);
                checkpoint(database, rotationId, "appointments", written);
                rotateAppointments(database, oldCrypto, newCrypto, config.batchSize(), written, progress);
                checkpoint(database, rotationId, "verification", written);

                progress.update("Verification: checking the new key against every field", written.documents);
                RotationReport.Mutable verified = scan(database, oldCrypto, newCrypto,
                        config.batchSize(), progress);
                if (verified.oldKeyFields != 0 || verified.plaintextFields != 0 || verified.errors != 0) {
                    throw new FieldCrypto.RotationException(
                            "Verification failed: old-key fields=" + verified.oldKeyFields
                                    + ", plaintext fields=" + verified.plaintextFields
                                    + ", errors=" + verified.errors);
                }

                complete(database, rotationId, written);
                return written.snapshot("ROTATE", Duration.between(started, Instant.now()));
            } catch (RuntimeException ex) {
                try {
                    fail(database, rotationId, written, ex);
                } catch (RuntimeException journalFailure) {
                    ex.addSuppressed(journalFailure);
                }
                throw ex;
            }
        }
    }

    private RotationReport.Mutable scan(MongoDatabase database, FieldCrypto oldCrypto,
                                        FieldCrypto newCrypto, int batchSize,
                                        ProgressListener progress) {
        RotationReport.Mutable stats = new RotationReport.Mutable();
        if (!active(USERS).isEmpty())
            scanCollection(database.getCollection(USERS), batchSize, stats, progress,
                    (document, ignored) -> scanUser(document, oldCrypto, newCrypto, stats));
        if (!active(OFFICES).isEmpty())
            scanCollection(database.getCollection(OFFICES), batchSize, stats, progress,
                    (document, ignored) -> scanOffice(document, oldCrypto, newCrypto, stats));
        if (!active(APPOINTMENTS).isEmpty())
            scanCollection(database.getCollection(APPOINTMENTS), batchSize, stats, progress,
                    (document, ignored) -> scanAppointment(document, oldCrypto, newCrypto, stats));
        return stats;
    }

    private void scanUser(Document user, FieldCrypto oldCrypto, FieldCrypto newCrypto,
                          RotationReport.Mutable stats) {
        Set<String> paths = active(USERS);
        rejectUnknownEncryptedPaths(user, USER_ENCRYPTED_PATHS, USERS, user.get("_id"));
        if (paths.contains("displayNameEncrypted"))
            scanValue(user.getString("displayNameEncrypted"), oldCrypto, newCrypto, stats, USERS, user.get("_id"), "displayNameEncrypted");
        if (paths.contains("telephoneEncrypted"))
            scanValue(user.getString("telephoneEncrypted"), oldCrypto, newCrypto, stats, USERS, user.get("_id"), "telephoneEncrypted");
        if (paths.contains("totpSecretEncrypted"))
            scanValue(user.getString("totpSecretEncrypted"), oldCrypto, newCrypto, stats, USERS, user.get("_id"), "totpSecretEncrypted");
    }

    private void scanOffice(Document office, FieldCrypto oldCrypto, FieldCrypto newCrypto,
                            RotationReport.Mutable stats) {
        Set<String> paths = active(OFFICES);
        rejectUnknownEncryptedPaths(office, OFFICE_ENCRYPTED_PATHS, OFFICES, office.get("_id"));
        if (paths.contains("addressEncrypted"))
            scanValue(office.getString("addressEncrypted"), oldCrypto, newCrypto, stats, OFFICES, office.get("_id"), "addressEncrypted");
        if (paths.contains("telephoneEncrypted"))
            scanValue(office.getString("telephoneEncrypted"), oldCrypto, newCrypto, stats, OFFICES, office.get("_id"), "telephoneEncrypted");
    }

    private void scanAppointment(Document appointment, FieldCrypto oldCrypto, FieldCrypto newCrypto,
                                 RotationReport.Mutable stats) {
        Object id = appointment.get("_id");
        Set<String> paths = active(APPOINTMENTS);
        rejectUnknownEncryptedPaths(appointment, APPOINTMENT_ENCRYPTED_PATHS, APPOINTMENTS, id);
        if (paths.contains("patientDisplayNameEncrypted"))
            scanValue(withLegacy(appointment, "patientDisplayNameEncrypted", "patientDisplayName"), oldCrypto, newCrypto, stats, APPOINTMENTS, id, "patientDisplayNameEncrypted");
        if (paths.contains("patientTelephoneEncrypted"))
            scanValue(appointment.getString("patientTelephoneEncrypted"), oldCrypto, newCrypto, stats, APPOINTMENTS, id, "patientTelephoneEncrypted");
        if (paths.contains("clinicNameEncrypted"))
            scanValue(withLegacy(appointment, "clinicNameEncrypted", "clinicName"), oldCrypto, newCrypto, stats, APPOINTMENTS, id, "clinicNameEncrypted");
        if (paths.contains("clinicianEncrypted"))
            scanValue(withLegacy(appointment, "clinicianEncrypted", "clinician"), oldCrypto, newCrypto, stats, APPOINTMENTS, id, "clinicianEncrypted");
        if (paths.contains("prescriptionEncrypted"))
            scanValue(withLegacy(appointment, "prescriptionEncrypted", "prescription"), oldCrypto, newCrypto, stats, APPOINTMENTS, id, "prescriptionEncrypted");

        List<Document> notes = documents(appointment.get("notes"));
        for (int index = 0; index < notes.size(); index++) {
            Document note = notes.get(index);
            stats.notes++;
            if (paths.contains("notes[].subjectEncrypted"))
                scanValue(withLegacy(note, "subjectEncrypted", "subject"), oldCrypto, newCrypto, stats, APPOINTMENTS, id, "notes[" + index + "].subjectEncrypted");
            if (paths.contains("notes[].noteTextEncrypted"))
                scanValue(withLegacy(note, "noteTextEncrypted", "noteText"), oldCrypto, newCrypto, stats, APPOINTMENTS, id, "notes[" + index + "].noteTextEncrypted");
            if (paths.contains("notes[].prescriptionEncrypted"))
                scanValue(withLegacy(note, "prescriptionEncrypted", "prescription"), oldCrypto, newCrypto, stats, APPOINTMENTS, id, "notes[" + index + "].prescriptionEncrypted");
        }
    }

    private void scanValue(String stored, FieldCrypto oldCrypto, FieldCrypto newCrypto,
                           RotationReport.Mutable stats, String collection, Object id, String field) {
        try {
            classify(stored, oldCrypto, newCrypto, stats);
        } catch (RuntimeException ex) {
            stats.errors++;
            throw new FieldCrypto.RotationException(
                    "Cannot decrypt " + collection + " document " + id + " field " + field, ex);
        }
    }

    private void rotateUsers(MongoDatabase database, FieldCrypto oldCrypto, FieldCrypto newCrypto,
                             int batchSize, RotationReport.Mutable stats, ProgressListener progress) {
        if (active(USERS).isEmpty()) return;
        transformCollection(database.getCollection(USERS), batchSize, stats, progress,
                (user, sets) -> {
                    if (active(USERS, "displayNameEncrypted"))
                        rotateAndSet(user, sets, "displayNameEncrypted", null, "displayNameLookupHash", oldCrypto, newCrypto, stats, USERS);
                    if (active(USERS, "telephoneEncrypted"))
                        rotateAndSet(user, sets, "telephoneEncrypted", null, null, oldCrypto, newCrypto, stats, USERS);
                    if (active(USERS, "totpSecretEncrypted"))
                        rotateAndSet(user, sets, "totpSecretEncrypted", null, null, oldCrypto, newCrypto, stats, USERS);
                });
    }

    private void rotateOffices(MongoDatabase database, FieldCrypto oldCrypto, FieldCrypto newCrypto,
                               int batchSize, RotationReport.Mutable stats, ProgressListener progress) {
        if (active(OFFICES).isEmpty()) return;
        transformCollection(database.getCollection(OFFICES), batchSize, stats, progress,
                (office, sets) -> {
                    if (active(OFFICES, "addressEncrypted"))
                        rotateAndSet(office, sets, "addressEncrypted", null, null, oldCrypto, newCrypto, stats, OFFICES);
                    if (active(OFFICES, "telephoneEncrypted"))
                        rotateAndSet(office, sets, "telephoneEncrypted", null, null, oldCrypto, newCrypto, stats, OFFICES);
                });
    }

    private void rotateAppointments(MongoDatabase database, FieldCrypto oldCrypto, FieldCrypto newCrypto,
                                    int batchSize, RotationReport.Mutable stats, ProgressListener progress) {
        if (active(APPOINTMENTS).isEmpty()) return;
        transformCollection(database.getCollection(APPOINTMENTS), batchSize, stats, progress,
                (appointment, sets) -> {
                    if (active(APPOINTMENTS, "patientDisplayNameEncrypted"))
                        rotateAndSet(appointment, sets, "patientDisplayNameEncrypted", "patientDisplayName", "patientDisplayNameLookupHash", oldCrypto, newCrypto, stats, APPOINTMENTS);
                    if (active(APPOINTMENTS, "patientTelephoneEncrypted"))
                        rotateAndSet(appointment, sets, "patientTelephoneEncrypted", null, null, oldCrypto, newCrypto, stats, APPOINTMENTS);
                    if (active(APPOINTMENTS, "clinicNameEncrypted"))
                        rotateAndSet(appointment, sets, "clinicNameEncrypted", "clinicName", null, oldCrypto, newCrypto, stats, APPOINTMENTS);
                    if (active(APPOINTMENTS, "clinicianEncrypted"))
                        rotateAndSet(appointment, sets, "clinicianEncrypted", "clinician", null, oldCrypto, newCrypto, stats, APPOINTMENTS);
                    if (active(APPOINTMENTS, "prescriptionEncrypted"))
                        rotateAndSet(appointment, sets, "prescriptionEncrypted", "prescription", null, oldCrypto, newCrypto, stats, APPOINTMENTS);

                    boolean rotateNotes = active(APPOINTMENTS, "notes[].subjectEncrypted")
                            || active(APPOINTMENTS, "notes[].noteTextEncrypted")
                            || active(APPOINTMENTS, "notes[].prescriptionEncrypted");
                    List<Document> notes = documents(appointment.get("notes"));
                    if (rotateNotes && !notes.isEmpty()) {
                        List<Document> rotatedNotes = new ArrayList<>(notes.size());
                        for (Document original : notes) {
                            Document note = new Document(original);
                            if (active(APPOINTMENTS, "notes[].subjectEncrypted")) {
                                rotateNested(note, "subjectEncrypted", "subject", oldCrypto, newCrypto, stats, APPOINTMENTS, appointment.get("_id"));
                                note.remove("subject");
                            }
                            if (active(APPOINTMENTS, "notes[].noteTextEncrypted")) {
                                rotateNested(note, "noteTextEncrypted", "noteText", oldCrypto, newCrypto, stats, APPOINTMENTS, appointment.get("_id"));
                                note.remove("noteText");
                            }
                            if (active(APPOINTMENTS, "notes[].prescriptionEncrypted")) {
                                rotateNested(note, "prescriptionEncrypted", "prescription", oldCrypto, newCrypto, stats, APPOINTMENTS, appointment.get("_id"));
                                note.remove("prescription");
                            }
                            rotatedNotes.add(note);
                            stats.notes++;
                        }
                        sets.put("notes", rotatedNotes);
                    }
                });
    }

    private void rotateAndSet(Document source, Document sets, String encryptedField,
                              String legacyField, String lookupField, FieldCrypto oldCrypto,
                              FieldCrypto newCrypto, RotationReport.Mutable stats, String collection) {
        String stored = withLegacy(source, encryptedField, legacyField);
        RotatedValue value = rotateValue(stored, oldCrypto, newCrypto, stats,
                collection, source.get("_id"), encryptedField);
        sets.put(encryptedField, value.encrypted());
        if (lookupField != null) sets.put(lookupField, newCrypto.lookupHash(value.plaintext()));
        if (legacyField != null) sets.put(legacyField, null);
    }

    private void rotateNested(Document note, String encryptedField, String legacyField,
                              FieldCrypto oldCrypto, FieldCrypto newCrypto,
                              RotationReport.Mutable stats, String collection, Object id) {
        String stored = withLegacy(note, encryptedField, legacyField);
        RotatedValue value = rotateValue(stored, oldCrypto, newCrypto, stats,
                collection, id, "notes." + encryptedField);
        note.put(encryptedField, value.encrypted());
    }

    private RotatedValue rotateValue(String stored, FieldCrypto oldCrypto, FieldCrypto newCrypto,
                                     RotationReport.Mutable stats, String collection,
                                     Object id, String field) {
        try {
            FieldState state = classify(stored, oldCrypto, newCrypto, stats);
            if (state == FieldState.NULL) return new RotatedValue(null, null);
            if (state == FieldState.NEW) return new RotatedValue(newCrypto.decrypt(stored), stored);
            String plaintext = state == FieldState.PLAIN ? stored : oldCrypto.decrypt(stored);
            stats.fieldsWritten++;
            return new RotatedValue(plaintext, newCrypto.encryptBlankAsNull(plaintext));
        } catch (RuntimeException ex) {
            stats.errors++;
            throw new FieldCrypto.RotationException(
                    "Cannot rotate " + collection + " document " + id + " field " + field, ex);
        }
    }

    private FieldState classify(String stored, FieldCrypto oldCrypto, FieldCrypto newCrypto,
                                RotationReport.Mutable stats) {
        if (stored == null || stored.isBlank()) {
            stats.nullFields++;
            return FieldState.NULL;
        }
        if (!stored.startsWith(FieldCrypto.PREFIX)) {
            stats.plaintextFields++;
            return FieldState.PLAIN;
        }
        try {
            oldCrypto.decrypt(stored);
            stats.oldKeyFields++;
            return FieldState.OLD;
        } catch (FieldCrypto.KeyMismatchException oldMismatch) {
            try {
                newCrypto.decrypt(stored);
                stats.newKeyFields++;
                return FieldState.NEW;
            } catch (RuntimeException newMismatch) {
                newMismatch.addSuppressed(oldMismatch);
                throw newMismatch;
            }
        }
    }

    private void scanCollection(MongoCollection<Document> collection, int batchSize,
                                RotationReport.Mutable stats, ProgressListener progress,
                                DocumentAction action) {
        Object lastId = null;
        while (true) {
            ensureNotInterrupted();
            List<Document> batch = fetchBatch(collection, lastId, batchSize);
            if (batch.isEmpty()) break;
            for (Document document : batch) {
                action.apply(document, new Document());
                stats.documents++;
                lastId = document.get("_id");
            }
            progress.update("Checking " + collection.getNamespace().getCollectionName(), stats.documents);
        }
    }

    private void transformCollection(MongoCollection<Document> collection, int batchSize,
                                     RotationReport.Mutable stats, ProgressListener progress,
                                     DocumentAction action) {
        Object lastId = null;
        while (true) {
            ensureNotInterrupted();
            List<Document> batch = fetchBatch(collection, lastId, batchSize);
            if (batch.isEmpty()) break;
            List<WriteModel<Document>> writes = new ArrayList<>(batch.size());
            for (Document document : batch) {
                Document sets = new Document();
                action.apply(document, sets);
                writes.add(new UpdateOneModel<>(eq("_id", document.get("_id")), new Document("$set", sets)));
                stats.documents++;
                lastId = document.get("_id");
            }
            collection.bulkWrite(writes, new BulkWriteOptions().ordered(true));
            progress.update("Rotated " + collection.getNamespace().getCollectionName(), stats.documents);
        }
    }

    private List<Document> fetchBatch(MongoCollection<Document> collection, Object lastId, int batchSize) {
        Bson filter = lastId == null ? new Document() : gt("_id", lastId);
        FindIterable<Document> result = collection.find(filter).sort(ascending("_id")).limit(batchSize);
        return result.into(new ArrayList<>(batchSize));
    }

    private void acquireLock(MongoDatabase database, String id, String from, String to, boolean resume) {
        acquireGlobalLock(database, id, resume);
        MongoCollection<Document> records = database.getCollection(RECORDS);
        Document record = new Document("_id", id)
                .append("fromKeyFingerprint", from)
                .append("toKeyFingerprint", to)
                .append("status", "IN_PROGRESS")
                .append("startedAt", new Date())
                .append("tool", "example-security-key-rotator");
        try {
            records.insertOne(record);
            return;
        } catch (MongoWriteException ex) {
            if (ex.getError().getCode() != 11000) {
                releaseGlobalLock(database, id);
                throw ex;
            }
        }

        Document existing = records.find(eq("_id", id)).first();
        if (existing == null) {
            releaseGlobalLock(database, id);
            throw new IllegalStateException("The rotation journal could not be read after a duplicate-key response");
        }
        String status = existing.getString("status");
        if ("COMPLETED".equals(status)) {
            releaseGlobalLock(database, id);
            throw new IllegalStateException("This exact rotation has already completed");
        }
        if (!resume) {
            releaseGlobalLock(database, id);
            throw new IllegalStateException("This rotation already exists with status " + status
                    + ". Select resume only after investigating the previous attempt.");
        }
        records.updateOne(eq("_id", id), combine(
                set("status", "IN_PROGRESS"), set("resumedAt", new Date()), set("message", "Resumed offline")));
    }

    private void acquireGlobalLock(MongoDatabase database, String rotationId, boolean resume) {
        MongoCollection<Document> locks = database.getCollection(LOCKS);
        try {
            locks.insertOne(new Document("_id", GLOBAL_LOCK_ID)
                    .append("rotationId", rotationId)
                    .append("status", "IN_PROGRESS")
                    .append("acquiredAt", new Date()));
            return;
        } catch (MongoWriteException ex) {
            if (ex.getError().getCode() != 11000) throw ex;
        }

        Document existing = locks.find(eq("_id", GLOBAL_LOCK_ID)).first();
        String existingRotation = existing == null ? null : existing.getString("rotationId");
        if (!resume || !rotationId.equals(existingRotation)) {
            throw new IllegalStateException("Another encryption rotation owns the global maintenance lock");
        }
        locks.updateOne(eq("_id", GLOBAL_LOCK_ID), combine(
                set("status", "IN_PROGRESS"), set("resumedAt", new Date())));
    }

    private void releaseGlobalLock(MongoDatabase database, String rotationId) {
        database.getCollection(LOCKS).deleteOne(new Document("_id", GLOBAL_LOCK_ID)
                .append("rotationId", rotationId));
    }

    private void checkpoint(MongoDatabase database, String id, String phase,
                            RotationReport.Mutable stats) {
        database.getCollection(RECORDS).updateOne(eq("_id", id), combine(
                set("phase", phase), set("documentsProcessed", stats.documents),
                set("fieldsWritten", stats.fieldsWritten), set("notesRotated", stats.notes),
                set("checkpointAt", new Date())));
    }

    private void complete(MongoDatabase database, String id, RotationReport.Mutable stats) {
        database.getCollection(RECORDS).updateOne(eq("_id", id), combine(
                set("status", "COMPLETED"), set("phase", "completed"),
                set("completedAt", new Date()), set("documentsProcessed", stats.documents),
                set("fieldsWritten", stats.fieldsWritten), set("notesRotated", stats.notes),
                set("message", "Offline rotation completed and verified")));
        releaseGlobalLock(database, id);
    }

    private void fail(MongoDatabase database, String id, RotationReport.Mutable stats, RuntimeException ex) {
        String message = Objects.toString(ex.getMessage(), ex.getClass().getSimpleName());
        if (message.length() > 500) message = message.substring(0, 500);
        database.getCollection(RECORDS).updateOne(eq("_id", id), combine(
                set("status", "FAILED"), set("failedAt", new Date()),
                set("documentsProcessed", stats.documents), set("fieldsWritten", stats.fieldsWritten),
                set("message", message)));
        database.getCollection(LOCKS).updateOne(eq("_id", GLOBAL_LOCK_ID), combine(
                set("status", "FAILED"), set("failedAt", new Date()), set("message", message)));
    }

    private static String withLegacy(Document document, String encryptedField, String legacyField) {
        String encrypted = document.getString(encryptedField);
        if (encrypted != null || legacyField == null) return encrypted;
        Object legacy = document.get(legacyField);
        return legacy instanceof String value && !value.isBlank() ? value : null;
    }

    @SuppressWarnings("unchecked")
    private static List<Document> documents(Object value) {
        if (!(value instanceof List<?> list)) return List.of();
        List<Document> result = new ArrayList<>(list.size());
        for (Object item : list) {
            if (item instanceof Document document) result.add(document);
            else if (item instanceof java.util.Map<?, ?> map) result.add(new Document((java.util.Map<String, Object>) map));
        }
        return result;
    }

    private static void rejectUnknownEncryptedPaths(Document document, Set<String> allowed,
                                                    String collection, Object id) {
        inspectEncryptedPaths(document, "", allowed, collection, id);
    }

    private static void inspectEncryptedPaths(Object value, String path, Set<String> allowed,
                                              String collection, Object id) {
        if (value instanceof String text) {
            if (text.startsWith(FieldCrypto.PREFIX) && !allowed.contains(path)) {
                throw new FieldCrypto.RotationException("Unsupported encrypted field " + collection
                        + " document " + id + " path " + path
                        + ". Update the rotator schema map before rotating.");
            }
            return;
        }
        if (value instanceof java.util.Map<?, ?> map) {
            for (java.util.Map.Entry<?, ?> entry : map.entrySet()) {
                String child = path.isEmpty() ? String.valueOf(entry.getKey())
                        : path + "." + entry.getKey();
                inspectEncryptedPaths(entry.getValue(), child, allowed, collection, id);
            }
            return;
        }
        if (value instanceof List<?> list) {
            String child = path + "[]";
            for (Object item : list) inspectEncryptedPaths(item, child, allowed, collection, id);
        }
    }

    private static void ensureNotInterrupted() {
        if (Thread.currentThread().isInterrupted()) {
            throw new FieldCrypto.RotationException("Rotation was cancelled between batches");
        }
    }

    private enum FieldState { NULL, PLAIN, OLD, NEW }
    private record RotatedValue(String plaintext, String encrypted) { }

    @FunctionalInterface
    private interface DocumentAction {
        void apply(Document document, Document sets);
    }
}
