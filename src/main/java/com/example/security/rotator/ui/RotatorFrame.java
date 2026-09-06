package com.example.security.rotator.ui;

import com.example.security.rotator.RotationConfig;
import com.example.security.rotator.RotationEngine;
import com.example.security.rotator.RotationReport;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingConstants;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;

public final class RotatorFrame extends JFrame {
    private static final long serialVersionUID = 1L;

    private static final Color PAGE = new Color(238, 242, 247);
    private static final Color CARD = Color.WHITE;
    private static final Color TEXT = new Color(23, 43, 77);
    private static final Color MUTED = new Color(89, 103, 125);
    private static final Color PRIMARY = new Color(13, 110, 253);
    private static final Color DANGER = new Color(220, 53, 69);

    private final JPasswordField mongoUri = new JPasswordField();
    private final JTextField database = new JTextField("example_security");
    private final JPasswordField oldPassphrase = new JPasswordField();
    private final JTextField oldSalt = new JTextField();
    private final JPasswordField newPassphrase = new JPasswordField();
    private final JTextField newSalt = new JTextField();
    private final JSpinner batchSize = new JSpinner(new SpinnerNumberModel(100, 1, 1000, 10));
    private final JCheckBox resume = new JCheckBox("Resume an investigated incomplete rotation");
    private final JCheckBox backupConfirmed = new JCheckBox("A current backup has been taken and verified");
    private final JCheckBox maintenanceConfirmed = new JCheckBox("All ExampleSecurity backends are stopped or drained");
    private final JTextArea output = new JTextArea(11, 72);
    private final JProgressBar progress = new JProgressBar();
    private final JLabel status = new JLabel("Ready");
    private final JButton connectButton = button("Test connection", new Color(108, 117, 125));
    private final JButton checkButton = button("Dry-run check", PRIMARY);
    private final JButton rotateButton = button("Rotate key and salt", DANGER);
    private final JButton cancelButton = button("Cancel after batch", new Color(108, 117, 125));
    private SwingWorker<RotationReport, String> worker;

    public RotatorFrame() {
        super("ExampleSecurity Key & Salt Rotator");
        installLookAndFeel();
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(900, 820));
        setSize(980, 900);
        setLocationRelativeTo(null);
        getContentPane().setBackground(PAGE);
        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(buildPage(), BorderLayout.CENTER);
        wireActions();
    }

    private JPanel buildPage() {
        JPanel page = new JPanel(new GridBagLayout());
        page.setBackground(PAGE);
        page.setBorder(new EmptyBorder(28, 28, 28, 28));

        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBackground(CARD);
        card.setBorder(new CompoundBorder(
                BorderFactory.createLineBorder(new Color(222, 226, 230)),
                new EmptyBorder(28, 32, 28, 32)));

        JLabel title = new JLabel("Encryption Key & Salt Rotator");
        title.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 27));
        title.setForeground(TEXT);
        title.setAlignmentX(LEFT_ALIGNMENT);
        card.add(title);

        JLabel subtitle = new JLabel("Offline maintenance utility for ExampleSecurity MongoDB");
        subtitle.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 15));
        subtitle.setForeground(MUTED);
        subtitle.setBorder(new EmptyBorder(4, 0, 22, 0));
        subtitle.setAlignmentX(LEFT_ALIGNMENT);
        card.add(subtitle);

        card.add(formPanel());
        card.add(Box.createVerticalStrut(14));
        card.add(confirmations());
        card.add(Box.createVerticalStrut(14));
        card.add(actions());
        card.add(Box.createVerticalStrut(14));

        progress.setIndeterminate(false);
        progress.setVisible(false);
        progress.setAlignmentX(LEFT_ALIGNMENT);
        card.add(progress);
        status.setForeground(MUTED);
        status.setBorder(new EmptyBorder(7, 0, 7, 0));
        status.setAlignmentX(LEFT_ALIGNMENT);
        card.add(status);

        output.setEditable(false);
        output.setLineWrap(true);
        output.setWrapStyleWord(true);
        output.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        output.setBackground(new Color(248, 249, 250));
        output.setForeground(TEXT);
        JScrollPane scroll = new JScrollPane(output);
        scroll.setAlignmentX(LEFT_ALIGNMENT);
        card.add(scroll);

        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;
        page.add(card, c);
        return page;
    }

    private JPanel formPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(CARD);
        panel.setAlignmentX(LEFT_ALIGNMENT);
        int row = 0;
        addField(panel, row++, "MongoDB connection URL", mongoUri,
                "Use the Atlas or TLS/allowlisted Krystal backup-style URL");
        addField(panel, row++, "Database", database, "Normally example_security");
        addField(panel, row++, "Old passphrase", oldPassphrase, "Current production passphrase");
        addField(panel, row++, "Old master salt (Base64)", oldSalt, "Existing salt; 16+ decoded bytes");
        addField(panel, row++, "New passphrase", newPassphrase, "Use a new long random word string");

        JPanel newSaltRow = new JPanel(new BorderLayout(8, 0));
        newSaltRow.setBackground(CARD);
        newSaltRow.add(newSalt, BorderLayout.CENTER);
        JButton generate = button("Generate 32-byte salt", PRIMARY);
        generate.addActionListener(event -> newSalt.setText(RotationConfig.generateSaltBase64()));
        newSaltRow.add(generate, BorderLayout.EAST);
        addField(panel, row++, "New master salt (Base64)", newSaltRow, "Generated with SecureRandom");

        addField(panel, row++, "Batch size", batchSize, "1–1000 documents; 100 recommended");

        JCheckBox show = new JCheckBox("Show connection URL and passphrases");
        show.setBackground(CARD);
        show.setForeground(MUTED);
        char echo = oldPassphrase.getEchoChar();
        show.addActionListener(event -> {
            char selected = show.isSelected() ? (char) 0 : echo;
            mongoUri.setEchoChar(selected);
            oldPassphrase.setEchoChar(selected);
            newPassphrase.setEchoChar(selected);
        });
        GridBagConstraints c = constraints(1, row);
        c.gridwidth = 2;
        panel.add(show, c);
        return panel;
    }

    private JPanel confirmations() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(new Color(255, 248, 230));
        panel.setBorder(new CompoundBorder(BorderFactory.createLineBorder(new Color(255, 193, 7)),
                new EmptyBorder(10, 12, 10, 12)));
        panel.setAlignmentX(LEFT_ALIGNMENT);
        for (JCheckBox box : List.of(backupConfirmed, maintenanceConfirmed, resume)) {
            box.setBackground(panel.getBackground());
            box.setForeground(TEXT);
            box.setAlignmentX(LEFT_ALIGNMENT);
            panel.add(box);
        }
        return panel;
    }

    private JPanel actions() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.setBackground(CARD);
        panel.setAlignmentX(LEFT_ALIGNMENT);
        cancelButton.setEnabled(false);
        panel.add(connectButton);
        panel.add(Box.createHorizontalStrut(8));
        panel.add(checkButton);
        panel.add(Box.createHorizontalStrut(8));
        panel.add(rotateButton);
        panel.add(Box.createHorizontalGlue());
        panel.add(cancelButton);
        return panel;
    }

    private void addField(JPanel panel, int row, String labelText, java.awt.Component component,
                          String helpText) {
        JLabel label = new JLabel(labelText);
        label.setFont(label.getFont().deriveFont(Font.BOLD));
        label.setForeground(TEXT);
        panel.add(label, constraints(0, row));

        GridBagConstraints field = constraints(1, row);
        field.weightx = 1;
        field.fill = GridBagConstraints.HORIZONTAL;
        panel.add(component, field);

        JLabel help = new JLabel(helpText);
        help.setForeground(MUTED);
        help.setFont(help.getFont().deriveFont(11f));
        GridBagConstraints hc = constraints(2, row);
        hc.anchor = GridBagConstraints.WEST;
        panel.add(help, hc);
    }

    private GridBagConstraints constraints(int x, int y) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = x;
        c.gridy = y;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(5, x == 0 ? 0 : 10, 5, 0);
        return c;
    }

    private void wireActions() {
        connectButton.addActionListener(event -> testConnection());
        checkButton.addActionListener(event -> start(false));
        rotateButton.addActionListener(event -> start(true));
        cancelButton.addActionListener(event -> {
            if (worker != null) worker.cancel(true);
        });
    }

    private void testConnection() {
        char[] uri = mongoUri.getPassword();
        setBusy(true, "Testing MongoDB connection…");
        SwingWorker<Void, Void> connectionWorker = new SwingWorker<>() {
            @Override protected Void doInBackground() {
                new RotationEngine().testConnection(uri, database.getText());
                return null;
            }

            @Override protected void done() {
                Arrays.fill(uri, '\0');
                try {
                    get();
                    output.setText("Connection successful.\n");
                    status.setText("MongoDB connection successful");
                } catch (Exception ex) {
                    showError(ex);
                } finally {
                    setBusy(false, status.getText());
                }
            }
        };
        connectionWorker.execute();
    }

    private void start(boolean rotate) {
        if (rotate && (!backupConfirmed.isSelected() || !maintenanceConfirmed.isSelected())) {
            JOptionPane.showMessageDialog(this,
                    "Confirm both the verified backup and maintenance shutdown first.",
                    "Rotation blocked", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (rotate) {
            String confirmation = JOptionPane.showInputDialog(this,
                    "This writes to MongoDB. Type ROTATE to continue:", "Final confirmation",
                    JOptionPane.WARNING_MESSAGE);
            if (!"ROTATE".equals(confirmation)) return;
        }

        final RotationConfig config;
        try {
            config = readConfig();
        } catch (RuntimeException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Invalid configuration",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }

        output.setText(rotate ? "Starting preflight and rotation…\n" : "Starting read-only dry run…\n");
        setBusy(true, rotate ? "Rotation running" : "Dry-run check running");
        worker = new SwingWorker<>() {
            @Override protected RotationReport doInBackground() {
                RotationEngine engine = new RotationEngine();
                return rotate
                        ? engine.rotate(config, (message, count) -> publish(message + " — " + count + " documents"))
                        : engine.check(config, (message, count) -> publish(message + " — " + count + " documents"));
            }

            @Override protected void process(List<String> chunks) {
                if (!chunks.isEmpty()) {
                    String latest = chunks.get(chunks.size() - 1);
                    status.setText(latest);
                    output.append(latest + System.lineSeparator());
                }
            }

            @Override protected void done() {
                try {
                    RotationReport report = get();
                    output.append(System.lineSeparator() + report.summary() + System.lineSeparator());
                    status.setText(rotate ? "Rotation completed and verified" : "Dry-run check completed");
                    JOptionPane.showMessageDialog(RotatorFrame.this,
                            rotate
                                    ? "Rotation completed and verified. Update both application servers to the new secrets before restarting them."
                                    : "Dry run completed without decryption errors.",
                            "Success", JOptionPane.INFORMATION_MESSAGE);
                } catch (ExecutionException ex) {
                    showError(ex.getCause());
                } catch (Exception ex) {
                    showError(ex);
                } finally {
                    config.close();
                    setBusy(false, status.getText());
                    worker = null;
                }
            }
        };
        cancelButton.setEnabled(true);
        worker.execute();
    }

    private RotationConfig readConfig() {
        return new RotationConfig(mongoUri.getPassword(), database.getText(),
                oldPassphrase.getPassword(), oldSalt.getText(), newPassphrase.getPassword(),
                newSalt.getText(), (Integer) batchSize.getValue(), resume.isSelected());
    }

    private void setBusy(boolean busy, String message) {
        connectButton.setEnabled(!busy);
        checkButton.setEnabled(!busy);
        rotateButton.setEnabled(!busy);
        cancelButton.setEnabled(busy && worker != null);
        progress.setVisible(busy);
        progress.setIndeterminate(busy);
        status.setText(message);
    }

    private void showError(Throwable error) {
        Throwable current = error;
        while (current.getCause() != null && current.getCause() != current) current = current.getCause();
        String message = current.getMessage();
        if (message == null || message.isBlank()) message = current.getClass().getSimpleName();
        output.append(System.lineSeparator() + "ERROR: " + message + System.lineSeparator());
        status.setText("Operation failed");
        JOptionPane.showMessageDialog(this, message, "Operation failed", JOptionPane.ERROR_MESSAGE);
    }

    private static JButton button(String text, Color background) {
        JButton button = new JButton(text);
        button.setOpaque(true);
        button.setBackground(background);
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);
        button.setBorder(new EmptyBorder(10, 16, 10, 16));
        return button;
    }

    private static void installLookAndFeel() {
        try {
            for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
            UIManager.put("Label.foreground", TEXT);
            UIManager.put("TextField.font", new Font(Font.SANS_SERIF, Font.PLAIN, 14));
            UIManager.put("PasswordField.font", new Font(Font.SANS_SERIF, Font.PLAIN, 14));
        } catch (Exception ignored) {
            // The platform look and feel remains fully functional.
        }
    }
}
