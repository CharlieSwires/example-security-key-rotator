package com.example.security.rotator;

import com.example.security.rotator.ui.RotatorFrame;

import javax.swing.SwingUtilities;
import java.util.Locale;
import java.util.Map;

public final class RotatorApplication {
    private RotatorApplication() { }

    public static void main(String[] args) {
        if (args.length > 0 && "--cli".equals(args[0])) {
            int exit = runCli(System.getenv());
            if (exit != 0) System.exit(exit);
            return;
        }
        SwingUtilities.invokeLater(() -> new RotatorFrame().setVisible(true));
    }

    static int runCli(Map<String, String> env) {
        String mode = env.getOrDefault("ROTATOR_MODE", "check").trim().toLowerCase(Locale.ROOT);
        try (RotationConfig config = RotationConfig.fromEnvironment(env)) {
            String projectDir = env.get("ROTATOR_MODEL_SOURCE_DIR");
            if (projectDir == null || projectDir.isBlank()) {
                throw new IllegalArgumentException("ROTATOR_MODEL_SOURCE_DIR is required and must point at the Java MongoDB model source directory");
            }
            ProjectSchemaScanner.SchemaReport schema = new ProjectSchemaScanner()
                    .scanAndRequireCompatible(java.nio.file.Path.of(projectDir));
            System.out.println(schema.summary());
            RotationEngine engine = new RotationEngine(schema);
            RotationReport report;
            if ("check".equals(mode)) {
                report = engine.check(config, ProgressListener.CONSOLE);
            } else if ("rotate".equals(mode)) {
                requireConfirmation(env, "APP_MAINTENANCE_CONFIRMED", "true");
                requireConfirmation(env, "BACKUP_CONFIRMED", "true");
                requireConfirmation(env, "ROTATION_CONFIRM", "ROTATE");
                report = engine.rotate(config, ProgressListener.CONSOLE);
            } else {
                throw new IllegalArgumentException("ROTATOR_MODE must be check or rotate");
            }
            System.out.println();
            System.out.println(report.summary());
            return report.errors() == 0 ? 0 : 2;
        } catch (Exception ex) {
            System.err.println("Rotation utility failed: " + safeMessage(ex));
            return 1;
        }
    }

    private static void requireConfirmation(Map<String, String> env, String name, String expected) {
        if (!expected.equals(env.get(name))) {
            throw new IllegalArgumentException(name + " must be exactly " + expected);
        }
    }

    private static String safeMessage(Throwable error) {
        Throwable current = error;
        while (current != null) {
            String message = current.getMessage();
            if (message != null && !message.isBlank()
                    && !"Tag mismatch".equalsIgnoreCase(message)
                    && !message.toLowerCase(Locale.ROOT).contains("tag mismatch")) {
                return message;
            }
            current = current.getCause();
        }
        return "Cryptographic operation failed. No safe diagnostic message was available.";
    }
}
