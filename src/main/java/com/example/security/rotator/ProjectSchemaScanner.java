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
 * Discovers encrypted MongoDB fields from a user-selected Java model source directory.
 *
 * Contract: String fields whose Java (or @Field) name ends in "Encrypted" are encrypted.
 * Project name, package name, collection names, model names and nesting are discovered.
 */
public final class ProjectSchemaScanner {
    private static final Pattern DOCUMENT = Pattern.compile(
            "@Document\\s*\\((?:[^)]*?collection\\s*=\\s*)?\\\"([^\\\"]+)\\\"[^)]*\\)", Pattern.DOTALL);
    private static final Pattern DOCUMENT_NO_ARG = Pattern.compile("@Document\\b(?!\\s*\\()|@Document\\s*\\(\\s*\\)");
    private static final Pattern CLASS = Pattern.compile("\\b(?:class|record)\\s+([A-Za-z_$][A-Za-z0-9_$]*)\\b");
    private static final Pattern FIELD = Pattern.compile(
            "(?s)(@Field\\s*\\(\\s*\\\"([^\\\"]+)\\\"\\s*\\)\\s*)?" +
            "(?:private|protected|public)\\s+(?:final\\s+)?([^;=]+?)\\s+([A-Za-z_$][A-Za-z0-9_$]*)\\s*(?:=[^;]*)?;");
    private static final Pattern LIST_TYPE = Pattern.compile("(?:List|Collection|Set|Iterable)\\s*<\\s*([A-Za-z_$][A-Za-z0-9_$.]*)\\s*>");

    public SchemaReport scan(Path modelSourceDirectory) {
        Path root = validateModelSourceDirectory(modelSourceDirectory);
        List<Path> javaFiles = new ArrayList<>();
        try (Stream<Path> paths = Files.walk(root)) {
            paths.filter(p -> p.toString().endsWith(".java")).forEach(javaFiles::add);
        } catch (IOException ex) {
            throw new IllegalArgumentException("Could not scan model source directory: " + ex.getMessage(), ex);
        }
        if (javaFiles.isEmpty()) {
            return new SchemaReport(root, Map.of(), Map.of(), 0,
                    List.of("No .java model files were found in the selected directory"));
        }

        Map<String, ClassInfo> classes = new LinkedHashMap<>();
        List<DocumentClass> documents = new ArrayList<>();
        for (Path file : javaFiles) parseFile(file, classes, documents);

        Map<String, Set<String>> encrypted = new LinkedHashMap<>();
        Map<String, Map<String, String>> lookupHashes = new LinkedHashMap<>();
        List<String> problems = new ArrayList<>();

        for (DocumentClass document : documents) {
            ClassInfo info = classes.get(document.className());
            if (info == null) continue;
            String collection = document.collection();
            if (collection == null || collection.isBlank()) {
                collection = lowerFirst(document.className());
            }
            Set<String> paths = encrypted.computeIfAbsent(collection, ignored -> new LinkedHashSet<>());
            Map<String, String> hashes = lookupHashes.computeIfAbsent(collection, ignored -> new LinkedHashMap<>());
            discover(info, "", classes, paths, hashes, new LinkedHashSet<>(), problems);
            if (paths.isEmpty()) {
                encrypted.remove(collection);
                lookupHashes.remove(collection);
            }
        }

        if (documents.isEmpty()) problems.add("No Spring Data @Document model classes were found");
        if (encrypted.isEmpty()) problems.add("No fields ending in Encrypted were found in any @Document model");
        return new SchemaReport(root, encrypted, lookupHashes, javaFiles.size(), problems);
    }

    public SchemaReport scanAndRequireCompatible(Path modelSourceDirectory) {
        SchemaReport report = scan(modelSourceDirectory);
        if (!report.compatible()) throw new IllegalArgumentException(report.problemSummary());
        return report;
    }

    private static Path validateModelSourceDirectory(Path path) {
        if (path == null || path.toString().isBlank())
            throw new IllegalArgumentException("MongoDB model source directory is required");
        Path root = path.toAbsolutePath().normalize();
        if (!Files.isDirectory(root))
            throw new IllegalArgumentException("Model source path is not a directory: " + root);
        return root;
    }

    private static void parseFile(Path path, Map<String, ClassInfo> classes, List<DocumentClass> documents) {
        try {
            String text = stripComments(Files.readString(path, StandardCharsets.UTF_8));
            Matcher classMatcher = CLASS.matcher(text);
            while (classMatcher.find()) {
                String className = classMatcher.group(1);
                int open = text.indexOf('{', classMatcher.end());
                if (open < 0) continue;
                int close = matchingBrace(text, open);
                if (close < 0) continue;
                String body = text.substring(open + 1, close);
                String directBody = removeNestedClassBodies(body);
                ClassInfo info = new ClassInfo(className, parseFields(directBody));
                classes.putIfAbsent(className, info);

                String prefix = text.substring(Math.max(0, classMatcher.start() - 1200), classMatcher.start());
                int previousClass = Math.max(prefix.lastIndexOf(" class "), prefix.lastIndexOf(" record "));
                String annotations = previousClass >= 0 ? prefix.substring(previousClass) : prefix;
                Matcher doc = DOCUMENT.matcher(annotations);
                String collection = null;
                boolean isDocument = false;
                while (doc.find()) { isDocument = true; collection = doc.group(1); }
                if (!isDocument && DOCUMENT_NO_ARG.matcher(annotations).find()) isDocument = true;
                if (isDocument) documents.add(new DocumentClass(className, collection));
            }
        } catch (IOException ex) {
            throw new IllegalArgumentException("Could not read " + path + ": " + ex.getMessage(), ex);
        }
    }

    private static List<FieldInfo> parseFields(String body) {
        List<FieldInfo> fields = new ArrayList<>();
        Matcher matcher = FIELD.matcher(body);
        while (matcher.find()) {
            String mongoName = matcher.group(2);
            String type = matcher.group(3).trim();
            String javaName = matcher.group(4);
            fields.add(new FieldInfo(javaName, mongoName == null ? javaName : mongoName, type));
        }
        return fields;
    }

    private static void discover(ClassInfo info, String prefix, Map<String, ClassInfo> classes,
                                 Set<String> encryptedPaths, Map<String, String> lookupHashes,
                                 Set<String> stack, List<String> problems) {
        if (!stack.add(info.name())) return;
        try {
            Map<String, FieldInfo> byJavaName = new LinkedHashMap<>();
            for (FieldInfo field : info.fields()) byJavaName.put(field.javaName(), field);

            for (FieldInfo field : info.fields()) {
                String mongoPath = prefix + field.mongoName();
                if (isString(field.type()) && field.mongoName().endsWith("Encrypted")) {
                    encryptedPaths.add(mongoPath);
                    String base = field.javaName().substring(0, field.javaName().length() - "Encrypted".length());
                    FieldInfo hash = byJavaName.get(base + "LookupHash");
                    if (hash != null && isString(hash.type())) lookupHashes.put(mongoPath, prefix + hash.mongoName());
                    continue;
                }

                String nestedType = nestedType(field.type());
                if (nestedType == null) continue;
                ClassInfo nested = classes.get(simpleName(nestedType));
                if (nested == null) continue;
                boolean array = LIST_TYPE.matcher(field.type()).find() || field.type().trim().endsWith("[]");
                discover(nested, mongoPath + (array ? "[]." : "."), classes,
                        encryptedPaths, lookupHashes, stack, problems);
            }
        } finally {
            stack.remove(info.name());
        }
    }

    private static boolean isString(String type) {
        String t = type.replace("java.lang.", "").trim();
        return "String".equals(t);
    }

    private static String nestedType(String type) {
        Matcher list = LIST_TYPE.matcher(type);
        if (list.find()) return list.group(1);
        String t = type.trim().replace("[]", "");
        if (t.contains("<") || isString(t) || t.matches("(?:boolean|byte|short|int|long|float|double|char|Boolean|Byte|Short|Integer|Long|Float|Double|Character|Object|LocalDate|LocalDateTime|Instant|Date|BigDecimal|BigInteger)")) return null;
        return t;
    }

    private static String simpleName(String type) {
        int dot = type.lastIndexOf('.');
        return dot < 0 ? type : type.substring(dot + 1);
    }

    private static String stripComments(String text) {
        return text.replaceAll("(?s)/\\*.*?\\*/", " ").replaceAll("(?m)//.*$", " ");
    }

    private static String removeNestedClassBodies(String body) {
        StringBuilder result = new StringBuilder(body);
        Matcher matcher = CLASS.matcher(body);
        while (matcher.find()) {
            int open = body.indexOf('{', matcher.end());
            if (open < 0) continue;
            int close = matchingBrace(body, open);
            if (close < 0) continue;
            for (int i = matcher.start(); i <= close && i < result.length(); i++) result.setCharAt(i, ' ');
        }
        return result.toString();
    }

    private static int matchingBrace(String text, int open) {
        int depth = 0;
        boolean string = false, character = false, escape = false;
        for (int i = open; i < text.length(); i++) {
            char c = text.charAt(i);
            if (escape) { escape = false; continue; }
            if ((string || character) && c == '\\') { escape = true; continue; }
            if (!character && c == '"') { string = !string; continue; }
            if (!string && c == '\'') { character = !character; continue; }
            if (string || character) continue;
            if (c == '{') depth++;
            else if (c == '}' && --depth == 0) return i;
        }
        return -1;
    }

    private static String lowerFirst(String value) {
        return value.isEmpty() ? value : Character.toLowerCase(value.charAt(0)) + value.substring(1);
    }

    private record ClassInfo(String name, List<FieldInfo> fields) { }
    private record FieldInfo(String javaName, String mongoName, String type) { }
    private record DocumentClass(String className, String collection) { }

    public record SchemaReport(Path modelSourceDirectory,
                               Map<String, Set<String>> collections,
                               Map<String, Map<String, String>> lookupHashes,
                               int javaFilesInspected,
                               List<String> problems) {
        public boolean compatible() { return problems.isEmpty(); }
        public String problemSummary() { return String.join(System.lineSeparator(), problems); }
        public String summary() {
            StringBuilder b = new StringBuilder();
            b.append("Model schema scan: ").append(modelSourceDirectory).append(System.lineSeparator());
            b.append("Java files inspected: ").append(javaFilesInspected).append(System.lineSeparator());
            collections.forEach((collection, paths) -> {
                b.append(collection).append(" -> ").append(paths).append(System.lineSeparator());
                Map<String, String> hashes = lookupHashes.get(collection);
                if (hashes != null && !hashes.isEmpty()) b.append("  lookup hashes -> ").append(hashes).append(System.lineSeparator());
            });
            b.append(compatible()
                    ? "Schema accepted. Only discovered *Encrypted paths will be checked/rotated."
                    : "SCHEMA ERROR:\n" + problemSummary());
            return b.toString();
        }
    }
}
