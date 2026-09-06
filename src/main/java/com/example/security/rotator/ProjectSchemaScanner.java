package com.example.security.rotator;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Reads the actual ExampleSecurity Java source tree before a rotation and
 * verifies that the encrypted MongoDB schema still matches the fields the
 * rotation engine is designed to process.
 */
public final class ProjectSchemaScanner {
    private static final Pattern DOCUMENT = Pattern.compile("@Document\\s*\\(\\s*collection\\s*=\\s*\"([^\"]+)\"");
    private static final Pattern ENCRYPTED_FIELD = Pattern.compile("\\b(?:private|protected|public)\\s+String\\s+([A-Za-z0-9_]+Encrypted)\\s*[;=]");

    /**
     * Paths the current rotation engine knows how to process safely.
     * The filesystem schema is authoritative: fields absent from the application source are
     * not required and are not touched. This map is only an upper safety bound, so a newly
     * introduced encrypted field still stops the rotation until support is added deliberately.
     */
    private static final Map<String, Set<String>> SUPPORTED = Map.of(
            "users", Set.of("displayNameEncrypted", "telephoneEncrypted", "totpSecretEncrypted"),
            "offices", Set.of("addressEncrypted", "telephoneEncrypted"),
            "patient_appointment_documents", Set.of(
                    "patientDisplayNameEncrypted", "patientTelephoneEncrypted", "clinicNameEncrypted",
                    "clinicianEncrypted", "prescriptionEncrypted", "notes[].subjectEncrypted",
                    "notes[].noteTextEncrypted", "notes[].prescriptionEncrypted")
    );

    public SchemaReport scan(Path projectRoot) {
        Path root = validateProjectRoot(projectRoot);
        Path javaRoot = root.resolve("backend/src/main/java");
        Map<String, Set<String>> found = new LinkedHashMap<>();
        List<String> inspected = new ArrayList<>();

        try (Stream<Path> paths = Files.walk(javaRoot)) {
            paths.filter(p -> p.toString().endsWith(".java")).forEach(path -> inspect(path, found, inspected));
        } catch (IOException ex) {
            throw new IllegalArgumentException("Could not scan ExampleSecurity source tree: " + ex.getMessage(), ex);
        }

        List<String> problems = new ArrayList<>();
        for (Map.Entry<String, Set<String>> actualEntry : found.entrySet()) {
            Set<String> supported = SUPPORTED.get(actualEntry.getKey());
            if (supported == null) {
                if (!actualEntry.getValue().isEmpty()) {
                    problems.add("Unsupported MongoDB collection with encrypted fields: "
                            + actualEntry.getKey() + " -> " + actualEntry.getValue());
                }
                continue;
            }
            Set<String> unsupported = new LinkedHashSet<>(actualEntry.getValue());
            unsupported.removeAll(supported);
            if (!unsupported.isEmpty()) {
                problems.add(actualEntry.getKey() + " has encrypted paths not yet supported by the rotation engine: "
                        + unsupported);
            }
        }
        if (found.isEmpty()) problems.add("No @Document MongoDB models with encrypted fields were found under backend/src/main/java");

        return new SchemaReport(root, found, inspected.size(), problems);
    }

    public SchemaReport scanAndRequireCompatible(Path projectRoot) {
        SchemaReport report = scan(projectRoot);
        if (!report.compatible()) throw new IllegalArgumentException(report.problemSummary());
        return report;
    }

    private static Path validateProjectRoot(Path path) {
        if (path == null) throw new IllegalArgumentException("ExampleSecurity project path is required");
        Path root = path.toAbsolutePath().normalize();
        if (!Files.isDirectory(root)) throw new IllegalArgumentException("ExampleSecurity project path is not a directory: " + root);
        if (!Files.isDirectory(root.resolve("backend/src/main/java"))) {
            throw new IllegalArgumentException("That directory does not look like ExampleSecurity: expected backend/src/main/java under " + root);
        }
        return root;
    }

    private static void inspect(Path path, Map<String, Set<String>> found, List<String> inspected) {
        try {
            String text = Files.readString(path, StandardCharsets.UTF_8);
            inspected.add(path.toString());
            Matcher document = DOCUMENT.matcher(text);
            if (!document.find()) return;
            String collection = document.group(1);
            Set<String> encrypted = found.computeIfAbsent(collection, ignored -> new LinkedHashSet<>());

            // Top-level encrypted String fields.
            Matcher field = ENCRYPTED_FIELD.matcher(text);
            while (field.find()) encrypted.add(field.group(1));

            // PatientClinicalNote is currently the only embedded encrypted array in ExampleSecurity.
            // Detect it from the source rather than assuming its fields are present.
            if (text.contains("class PatientClinicalNote") && text.contains("List<PatientClinicalNote> notes")) {
                int nestedStart = text.indexOf("class PatientClinicalNote");
                String nested = text.substring(nestedStart);
                Matcher nestedField = ENCRYPTED_FIELD.matcher(nested);
                while (nestedField.find()) {
                    String name = nestedField.group(1);
                    encrypted.remove(name); // remove the unqualified nested match added by whole-file scan
                    encrypted.add("notes[]." + name);
                }
            }
        } catch (IOException ex) {
            throw new RuntimeException("Could not read " + path + ": " + ex.getMessage(), ex);
        }
    }

    public record SchemaReport(Path projectRoot, Map<String, Set<String>> collections,
                               int javaFilesInspected, List<String> problems) {
        public boolean compatible() { return problems.isEmpty(); }
        public String problemSummary() { return String.join(System.lineSeparator(), problems); }
        public String summary() {
            StringBuilder b = new StringBuilder();
            b.append("Filesystem schema scan: ").append(projectRoot).append(System.lineSeparator());
            b.append("Java files inspected: ").append(javaFilesInspected).append(System.lineSeparator());
            collections.forEach((collection, paths) -> b.append(collection).append(" -> ").append(paths).append(System.lineSeparator()));
            b.append(compatible()
                    ? "Filesystem schema accepted. Only the encrypted paths listed above will be checked/rotated."
                    : "SCHEMA MISMATCH:\n" + problemSummary());
            return b.toString();
        }
    }
}
