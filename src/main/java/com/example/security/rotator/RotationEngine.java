package com.example.security.rotator;

import com.mongodb.MongoWriteException;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.BulkWriteOptions;
import com.mongodb.client.model.ReplaceOneModel;
import com.mongodb.client.model.WriteModel;
import org.bson.Document;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static com.mongodb.client.model.Filters.eq;
import static com.mongodb.client.model.Filters.gt;
import static com.mongodb.client.model.Sorts.ascending;
import static com.mongodb.client.model.Updates.combine;
import static com.mongodb.client.model.Updates.set;

/** Generic filesystem-schema driven MongoDB field key/salt rotator. */
public final class RotationEngine {
    private static final String RECORDS = "crypto_rotation_records";
    private static final String LOCKS = "crypto_rotation_locks";
    private static final String GLOBAL_LOCK_ID = "field-crypto-global";

    private final Map<String, Set<String>> encryptedPaths;
    private final Map<String, Map<String, String>> lookupHashPaths;

    public RotationEngine(ProjectSchemaScanner.SchemaReport schema) {
        this(schema.collections(), schema.lookupHashes());
    }

    public RotationEngine(Map<String, Set<String>> encryptedPaths,
                          Map<String, Map<String, String>> lookupHashPaths) {
        if (encryptedPaths == null || encryptedPaths.isEmpty())
            throw new IllegalArgumentException("Filesystem-derived encrypted schema is required");
        this.encryptedPaths = encryptedPaths.entrySet().stream().collect(java.util.stream.Collectors.toUnmodifiableMap(
                Map.Entry::getKey, e -> Set.copyOf(e.getValue())));
        this.lookupHashPaths = lookupHashPaths == null ? Map.of() : lookupHashPaths.entrySet().stream()
                .collect(java.util.stream.Collectors.toUnmodifiableMap(Map.Entry::getKey, e -> Map.copyOf(e.getValue())));
    }

    public void testConnection(char[] mongoUri, String database) {
        if (mongoUri == null || mongoUri.length == 0) throw new IllegalArgumentException("MongoDB URI is required");
        if (database == null || database.isBlank()) throw new IllegalArgumentException("Database name is required");
        try (MongoClient client = MongoClients.create(new String(mongoUri))) {
            client.getDatabase(database.trim()).runCommand(new Document("ping", 1));
        }
    }

    public void testConnection(RotationConfig config) {
        try (MongoClient client = MongoClients.create(config.mongoUri())) {
            client.getDatabase(config.database()).runCommand(new Document("ping", 1));
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

            progress.update("Preflight: verifying discovered encrypted fields", 0);
            scan(database, oldCrypto, newCrypto, config.batchSize(), progress);
            acquireLock(database, rotationId, fromFingerprint, toFingerprint, config.resume());

            RotationReport.Mutable written = new RotationReport.Mutable();
            try {
                for (Map.Entry<String, Set<String>> entry : encryptedPaths.entrySet()) {
                    rotateCollection(database.getCollection(entry.getKey()), entry.getKey(), entry.getValue(),
                            oldCrypto, newCrypto, config.batchSize(), written, progress);
                    checkpoint(database, rotationId, "collection:" + entry.getKey(), written);
                }
                checkpoint(database, rotationId, "verification", written);
                RotationReport.Mutable verified = scan(database, oldCrypto, newCrypto, config.batchSize(), progress);
                if (verified.oldKeyFields != 0 || verified.plaintextFields != 0 || verified.errors != 0) {
                    throw new FieldCrypto.RotationException("Verification failed: old-key fields=" + verified.oldKeyFields
                            + ", plaintext fields=" + verified.plaintextFields + ", errors=" + verified.errors);
                }
                complete(database, rotationId, written);
                return written.snapshot("ROTATE", Duration.between(started, Instant.now()));
            } catch (RuntimeException ex) {
                try { fail(database, rotationId, written, ex); } catch (RuntimeException journalFailure) { ex.addSuppressed(journalFailure); }
                throw ex;
            }
        }
    }

    private RotationReport.Mutable scan(MongoDatabase database, FieldCrypto oldCrypto, FieldCrypto newCrypto,
                                        int batchSize, ProgressListener progress) {
        RotationReport.Mutable stats = new RotationReport.Mutable();
        for (Map.Entry<String, Set<String>> entry : encryptedPaths.entrySet()) {
            String collectionName = entry.getKey();
            MongoCollection<Document> collection = database.getCollection(collectionName);
            Object lastId = null;
            while (true) {
                ensureNotInterrupted();
                List<Document> batch = fetchBatch(collection, lastId, batchSize);
                if (batch.isEmpty()) break;
                for (Document document : batch) {
                    rejectUndiscoveredEncryptedPaths(document, entry.getValue(), collectionName);
                    for (String path : entry.getValue()) {
                        visitPath(document, path, (parent, leaf, displayPath) ->
                                scanValue(asString(parent.get(leaf), collectionName, document.get("_id"), displayPath),
                                        oldCrypto, newCrypto, stats, collectionName, document.get("_id"), displayPath));
                    }
                    stats.documents++;
                    lastId = document.get("_id");
                }
                progress.update("Checking " + collectionName, stats.documents);
            }
        }
        return stats;
    }

    private void rotateCollection(MongoCollection<Document> collection, String collectionName, Set<String> paths,
                                  FieldCrypto oldCrypto, FieldCrypto newCrypto, int batchSize,
                                  RotationReport.Mutable stats, ProgressListener progress) {
        Object lastId = null;
        while (true) {
            ensureNotInterrupted();
            List<Document> batch = fetchBatch(collection, lastId, batchSize);
            if (batch.isEmpty()) break;
            List<WriteModel<Document>> writes = new ArrayList<>();
            for (Document document : batch) {
                boolean[] changed = {false};
                for (String path : paths) {
                    String lookupPath = lookupHashPaths.getOrDefault(collectionName, Map.of()).get(path);
                    visitPath(document, path, (parent, leaf, displayPath) -> {
                        String stored = asString(parent.get(leaf), collectionName, document.get("_id"), displayPath);
                        RotatedValue value = rotateValue(stored, oldCrypto, newCrypto, stats,
                                collectionName, document.get("_id"), displayPath);
                        if (value.encrypted() != null && !Objects.equals(stored, value.encrypted())) {
                            parent.put(leaf, value.encrypted());
                            changed[0] = true;
                        }
                        if (value.plaintext() != null && lookupPath != null) {
                            String hash = newCrypto.lookupHash(value.plaintext());
                            if (setParallelPathValue(document, path, lookupPath, parent, hash)) changed[0] = true;
                        }
                    });
                }
                if (changed[0]) writes.add(new ReplaceOneModel<>(eq("_id", document.get("_id")), document));
                stats.documents++;
                lastId = document.get("_id");
            }
            if (!writes.isEmpty()) collection.bulkWrite(writes, new BulkWriteOptions().ordered(true));
            progress.update("Rotating " + collectionName, stats.documents);
        }
    }

    private static boolean setParallelPathValue(Document root, String encryptedPath, String lookupPath,
                                                Document encryptedParent, String value) {
        String encryptedParentPath = parentPath(encryptedPath);
        String lookupParentPath = parentPath(lookupPath);
        String lookupLeaf = leafName(lookupPath);
        if (encryptedParentPath.equals(lookupParentPath)) {
            Object old = encryptedParent.put(lookupLeaf, value);
            return !Objects.equals(old, value);
        }
        // Scanner only pairs sibling FooEncrypted/FooLookupHash fields. Refuse a future ambiguous mapping.
        throw new IllegalArgumentException("Lookup hash path is not a sibling of encrypted path: "
                + encryptedPath + " -> " + lookupPath);
    }

    private void scanValue(String stored, FieldCrypto oldCrypto, FieldCrypto newCrypto,
                           RotationReport.Mutable stats, String collection, Object id, String field) {
        try {
            classify(stored, oldCrypto, newCrypto, stats);
        } catch (RuntimeException ex) {
            stats.errors++;
            throw fieldFailure("Dry-run decryption failed", collection, id, field, ex);
        }
    }

    private RotatedValue rotateValue(String stored, FieldCrypto oldCrypto, FieldCrypto newCrypto,
                                     RotationReport.Mutable stats, String collection, Object id, String field) {
        try {
            FieldState state = classify(stored, oldCrypto, newCrypto, stats);
            if (state == FieldState.NULL) return new RotatedValue(null, null);
            if (state == FieldState.NEW) return new RotatedValue(newCrypto.decrypt(stored), stored);
            String plaintext = state == FieldState.PLAIN ? stored : oldCrypto.decrypt(stored);
            stats.fieldsWritten++;
            return new RotatedValue(plaintext, newCrypto.encryptBlankAsNull(plaintext));
        } catch (RuntimeException ex) {
            stats.errors++;
            throw fieldFailure("Rotation failed", collection, id, field, ex);
        }
    }

    private FieldState classify(String stored, FieldCrypto oldCrypto, FieldCrypto newCrypto, RotationReport.Mutable stats) {
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
            } catch (FieldCrypto.KeyMismatchException newMismatch) {
                newMismatch.addSuppressed(oldMismatch);
                throw new FieldCrypto.KeyMismatchException(
                        "Ciphertext cannot be authenticated with either the supplied OLD key/salt or NEW key/salt",
                        newMismatch);
            } catch (FieldCrypto.RotationException corruptWithNewKey) {
                corruptWithNewKey.addSuppressed(oldMismatch);
                throw new FieldCrypto.RotationException(
                        "Encrypted value is malformed or corrupt; it could not be parsed as a valid " + FieldCrypto.PREFIX + " payload",
                        corruptWithNewKey);
            }
        } catch (FieldCrypto.RotationException corruptPayload) {
            throw new FieldCrypto.RotationException(
                    "Encrypted value is malformed or corrupt; it could not be parsed as a valid " + FieldCrypto.PREFIX + " payload",
                    corruptPayload);
        }
    }

    private static FieldCrypto.RotationException fieldFailure(String heading, String collection, Object id,
                                                               String field, RuntimeException cause) {
        String reason;
        if (cause instanceof FieldCrypto.KeyMismatchException) {
            reason = "AES-GCM authentication failed: this ciphertext matches neither the supplied OLD key/salt "
                    + "nor the supplied NEW key/salt. Check the old passphrase and master salt first; if most "
                    + "records succeed, this individual value may have been encrypted with a different historical key/salt.";
        } else {
            reason = Objects.toString(cause.getMessage(), cause.getClass().getSimpleName());
        }
        return new FieldCrypto.RotationException(heading
                + "\nCollection: " + collection
                + "\nDocument _id: " + id
                + "\nField: " + field
                + "\nReason: " + reason, cause);
    }

    private static void visitPath(Document root, String path, LeafVisitor visitor) {
        String[] segments = path.split("\\.");
        visit(root, segments, 0, "", visitor);
    }

    @SuppressWarnings("unchecked")
    private static void visit(Object current, String[] segments, int index, String display, LeafVisitor visitor) {
        if (!(current instanceof Document document) || index >= segments.length) return;
        String segment = segments[index];
        boolean array = segment.endsWith("[]");
        String name = array ? segment.substring(0, segment.length() - 2) : segment;
        String nextDisplay = display.isEmpty() ? name : display + "." + name;
        if (index == segments.length - 1) {
            if (array) throw new IllegalArgumentException("Encrypted leaf itself cannot be an array: " + String.join(".", segments));
            visitor.accept(document, name, nextDisplay);
            return;
        }
        Object value = document.get(name);
        if (array) {
            if (value == null) return;
            if (!(value instanceof List<?> list)) throw new IllegalArgumentException("Expected array at " + nextDisplay);
            for (int i = 0; i < list.size(); i++) {
                Object item = list.get(i);
                Document nested = toDocument(item);
                if (nested == null) continue;
                visit(nested, segments, index + 1, nextDisplay + "[" + i + "]", visitor);
                if (!(item instanceof Document)) ((List<Object>) list).set(i, nested);
            }
        } else {
            Document nested = toDocument(value);
            if (nested != null) visit(nested, segments, index + 1, nextDisplay, visitor);
        }
    }

    @SuppressWarnings("unchecked")
    private static Document toDocument(Object value) {
        if (value instanceof Document document) return document;
        if (value instanceof Map<?, ?> map) return new Document((Map<String, Object>) map);
        return null;
    }

    private static String asString(Object value, String collection, Object id, String field) {
        if (value == null) return null;
        if (value instanceof String string) return string;
        throw new FieldCrypto.RotationException("Expected String or null in " + collection + " document " + id
                + " field " + field + " but found " + value.getClass().getSimpleName());
    }

    private static void rejectUndiscoveredEncryptedPaths(Document document, Set<String> discovered, String collection) {
        Set<String> actual = new LinkedHashSet<>();
        collectEncryptedPaths(document, "", actual);
        actual.removeAll(discovered);
        if (!actual.isEmpty()) {
            throw new FieldCrypto.RotationException("MongoDB collection " + collection
                    + " contains *Encrypted paths not present in the selected Java model source: " + actual);
        }
    }

    private static void collectEncryptedPaths(Object value, String prefix, Set<String> paths) {
        if (value instanceof Document document) {
            for (Map.Entry<String, Object> entry : document.entrySet()) {
                String path = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
                if (entry.getKey().endsWith("Encrypted")) paths.add(path);
                Object child = entry.getValue();
                if (child instanceof List<?>) collectEncryptedPaths(child, path + "[]", paths);
                else if (child instanceof Document || child instanceof Map<?, ?>) collectEncryptedPaths(child, path, paths);
            }
        } else if (value instanceof Map<?, ?> map) {
            collectEncryptedPaths(new Document((Map<String, Object>) map), prefix, paths);
        } else if (value instanceof List<?> list) {
            for (Object item : list) collectEncryptedPaths(item, prefix, paths);
        }
    }

    private static List<Document> fetchBatch(MongoCollection<Document> collection, Object lastId, int batchSize) {
        List<Document> batch = new ArrayList<>(batchSize);
        var iterable = lastId == null ? collection.find() : collection.find(gt("_id", lastId));
        iterable.sort(ascending("_id")).limit(batchSize).into(batch);
        return batch;
    }

    private void acquireLock(MongoDatabase database, String rotationId, String fromFingerprint,
                             String toFingerprint, boolean resume) {
        MongoCollection<Document> locks = database.getCollection(LOCKS);
        Document existing = locks.find(eq("_id", GLOBAL_LOCK_ID)).first();
        if (existing != null && !rotationId.equals(existing.getString("rotationId"))) {
            throw new FieldCrypto.RotationException("Another/incomplete rotation lock exists: " + existing.toJson());
        }
        if (existing != null && !resume && !"COMPLETED".equals(existing.getString("status"))) {
            throw new FieldCrypto.RotationException("An incomplete rotation exists. Investigate it, then explicitly enable Resume.");
        }
        if (existing == null) {
            try {
                locks.insertOne(new Document("_id", GLOBAL_LOCK_ID).append("rotationId", rotationId)
                        .append("status", "RUNNING").append("startedAt", new Date())
                        .append("fromFingerprint", fromFingerprint).append("toFingerprint", toFingerprint));
            } catch (MongoWriteException ex) { throw new FieldCrypto.RotationException("Could not acquire global rotation lock", ex); }
            database.getCollection(RECORDS).replaceOne(eq("_id", rotationId),
                    new Document("_id", rotationId).append("status", "RUNNING").append("phase", "preflight-complete")
                            .append("startedAt", new Date()).append("fromFingerprint", fromFingerprint)
                            .append("toFingerprint", toFingerprint).append("tool", "filesystem-schema-key-rotator"),
                    new com.mongodb.client.model.ReplaceOptions().upsert(true));
        }
    }

    private void checkpoint(MongoDatabase database, String id, String phase, RotationReport.Mutable stats) {
        database.getCollection(RECORDS).updateOne(eq("_id", id), combine(set("phase", phase),
                set("documentsProcessed", stats.documents), set("fieldsWritten", stats.fieldsWritten), set("checkpointAt", new Date())));
    }

    private void complete(MongoDatabase database, String id, RotationReport.Mutable stats) {
        database.getCollection(RECORDS).updateOne(eq("_id", id), combine(set("status", "COMPLETED"), set("phase", "completed"),
                set("completedAt", new Date()), set("documentsProcessed", stats.documents), set("fieldsWritten", stats.fieldsWritten),
                set("message", "Offline rotation completed and verified")));
        database.getCollection(LOCKS).deleteOne(new Document("_id", GLOBAL_LOCK_ID).append("rotationId", id));
    }

    private void fail(MongoDatabase database, String id, RotationReport.Mutable stats, RuntimeException ex) {
        String message = Objects.toString(ex.getMessage(), ex.getClass().getSimpleName());
        if (message.length() > 500) message = message.substring(0, 500);
        database.getCollection(RECORDS).updateOne(eq("_id", id), combine(set("status", "FAILED"), set("failedAt", new Date()),
                set("documentsProcessed", stats.documents), set("fieldsWritten", stats.fieldsWritten), set("message", message)));
        database.getCollection(LOCKS).updateOne(eq("_id", GLOBAL_LOCK_ID), combine(set("status", "FAILED"), set("failedAt", new Date()), set("message", message)));
    }

    private static void ensureNotInterrupted() {
        if (Thread.currentThread().isInterrupted()) throw new FieldCrypto.RotationException("Rotation cancelled after the current batch");
    }

    private static String parentPath(String path) { int i = path.lastIndexOf('.'); return i < 0 ? "" : path.substring(0, i); }
    private static String leafName(String path) { int i = path.lastIndexOf('.'); return i < 0 ? path : path.substring(i + 1); }

    private enum FieldState { NULL, PLAIN, OLD, NEW }
    private record RotatedValue(String plaintext, String encrypted) { }
    @FunctionalInterface private interface LeafVisitor { void accept(Document parent, String leaf, String displayPath); }
}
