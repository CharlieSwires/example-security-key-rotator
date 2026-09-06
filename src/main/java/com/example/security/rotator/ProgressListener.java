package com.example.security.rotator;

@FunctionalInterface
public interface ProgressListener {
    void update(String message, long processedDocuments);

    ProgressListener CONSOLE = (message, count) ->
            System.out.printf("%s (%,d documents)%n", message, count);
}
