package com.example.security.random.words.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public final class RandomPassphraseGenerator {

    private static final int DEFAULT_WORD_COUNT = 16;

    private final List<String> words;
    private final SecureRandom secureRandom;

    public RandomPassphraseGenerator(Path wordListPath) throws IOException {
        this.words = loadEffWordList(wordListPath);
        this.secureRandom = createSecureRandom();

        if (words.size() < 7_000) {
            throw new IllegalArgumentException(
                    "Word list looks too small. Expected the EFF long list with 7,776 words."
            );
        }
    }

    public String generatePassphrase() {
        return generatePassphrase(DEFAULT_WORD_COUNT);
    }

    public String generatePassphrase(int wordCount) {
        if (wordCount < 8) {
            throw new IllegalArgumentException("Use at least 8 words. For your use-case, prefer 16.");
        }

        List<String> selected = new ArrayList<>(wordCount);

        for (int i = 0; i < wordCount; i++) {
            int index = secureRandom.nextInt(words.size());
            selected.add(words.get(index));
        }

        return String.join(" ", selected);
    }

    private static List<String> loadEffWordList(Path path) throws IOException {
        List<String> result = new ArrayList<>();

        for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
            line = line.trim();

            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            // EFF format is usually:
            // 11111	abacus
            // 11112	abdomen
            String[] parts = line.split("\\s+");

            if (parts.length >= 2) {
                result.add(parts[1].trim());
            }
        }

        if (result.isEmpty()) {
            throw new IllegalArgumentException("No words loaded from " + path);
        }

        return List.copyOf(result);
    }

    private static SecureRandom createSecureRandom() {
        try {
            // May block briefly on some systems, but gives the JVM's configured strong RNG.
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            // Fallback is still cryptographically suitable on normal modern JVMs.
            return new SecureRandom();
        }
    }

    public static void main(String[] args) throws Exception {
        Path wordListPath = Path.of(
                args.length > 0 ? args[0] : "c:/users/charl/eclipse-workspace/example-security-key-rotator/src/main/java/com/example/security/random/words/util/eff_large_wordlist.txt"
        );

        RandomPassphraseGenerator generator =
                new RandomPassphraseGenerator(wordListPath);

        String passphrase = generator.generatePassphrase(16);

        System.out.println(passphrase);
    }
}