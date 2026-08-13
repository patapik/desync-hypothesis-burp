package com.maciejgojny.desync.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionType;
import com.maciejgojny.desync.Hypothesis;
import com.maciejgojny.desync.gen.HypothesisGenerator;
import com.maciejgojny.desync.replay.ClassifyResult;
import com.maciejgojny.desync.replay.DesyncReplayer;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;

public class CortexTab extends JPanel {

    private static final String OOB_ID_PREFIX = "spc-absolute-form-oob";
    private static final String OOB_PROBE_PATH = "/desync-check-spc-oob";
    private static final int VERDICT_COLUMN = 3;

    private final MontoyaApi api;
    private final DesyncReplayer replayer;

    private final JTextField baseField = new JTextField("/desync-check", 20);
    private final JTextField smuggledPathField = new JTextField("/desync-check-smuggled", 20);
    private final JTextField smuggledHostField = new JTextField("x", 10);
    private final JTextField followupPathField = new JTextField("/desync-check-followup", 20);
    private final JTextField authorityField = new JTextField("", 20);
    private final JTextField targetHostField = new JTextField("target.example.com", 20);
    private final JTextField targetPortField = new JTextField("443", 6);
    private final JCheckBox tlsCheck = new JCheckBox("TLS", true);
    private final JCheckBox collaboratorCheck = new JCheckBox("OOB via Burp Collaborator", true);
    private final JTextField maxField = new JTextField("0", 6);
    private JButton runButton;

    private final DefaultTableModel tableModel = new DefaultTableModel(
            new Object[]{"ID", "Category", "Expect", "Verdict", "First", "Followup", "Time (ms)"}, 0);

    public CortexTab(MontoyaApi api, DesyncReplayer replayer) {
        this.api = api;
        this.replayer = replayer;
        buildUi();
    }

    private void buildUi() {
        setLayout(new BorderLayout());

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;

        int row = 0;
        addRow(form, c, row++, "Target host", targetHostField);
        addRow(form, c, row++, "Target port", targetPortField);
        addRow(form, c, row++, "Base path", baseField);
        addRow(form, c, row++, "Smuggled path", smuggledPathField);
        addRow(form, c, row++, "Smuggled host", smuggledHostField);
        addRow(form, c, row++, "Followup path", followupPathField);
        addRow(form, c, row++, "OOB authority (manual)", authorityField);
        addRow(form, c, row++, "Max hypotheses (0=all)", maxField);

        c.gridx = 0;
        c.gridy = row;
        form.add(tlsCheck, c);
        c.gridx = 1;
        form.add(collaboratorCheck, c);
        row++;

        runButton = new JButton("Run desync scan");
        runButton.addActionListener(e -> runScan());
        c.gridx = 1;
        c.gridy = row;
        form.add(runButton, c);

        add(form, BorderLayout.NORTH);
        add(new JScrollPane(new JTable(tableModel)), BorderLayout.CENTER);
    }

    private void addRow(JPanel panel, GridBagConstraints c, int row, String label, JComponent field) {
        c.gridx = 0;
        c.gridy = row;
        panel.add(new JLabel(label), c);
        c.gridx = 1;
        panel.add(field, c);
    }

    private void runScan() {
        // Guard against overlapping scans: a scan stays alive ~12s after the table
        // looks done (OOB polling), and two workers publishing into the same cleared
        // table produce duplicate/misordered rows and socket contention.
        runButton.setEnabled(false);
        tableModel.setRowCount(0);

        if (targetHostField.getText().trim().isEmpty()) {
            api.logging().logToError("[scan] target host is empty — aborting");
            runButton.setEnabled(true);
            return;
        }

        // Fresh, single-use generator per scan: keeps per-scan config off any shared state.
        HypothesisGenerator generator = new HypothesisGenerator();
        generator.setBase(baseField.getText().trim());
        generator.setSmuggledPath(smuggledPathField.getText().trim());
        generator.setSmuggledHost(smuggledHostField.getText().trim());
        generator.setFollowupPath(followupPathField.getText().trim());

        // OOB authority: prefer a live Burp Collaborator payload (native OOB server);
        // fall back to the manually typed authority if Collaborator is off/unavailable.
        CollaboratorClient collabClient = null;
        if (collaboratorCheck.isSelected()) {
            try {
                collabClient = api.collaborator().createClient();
                CollaboratorPayload payload = collabClient.generatePayload();
                generator.setSmuggledAuthority(payload.toString());
                api.logging().logToOutput("[OOB] absolute-form SSRF probe authority = " + payload);
            } catch (Exception ex) {
                api.logging().logToError("[OOB] Collaborator unavailable, using manual authority: " + ex);
                collabClient = null;
                generator.setSmuggledAuthority(authorityField.getText().trim());
            }
        } else {
            generator.setSmuggledAuthority(authorityField.getText().trim());
        }

        int max;
        try {
            max = Integer.parseInt(maxField.getText().trim());
        } catch (NumberFormatException e) {
            max = 0;
        }
        String host = targetHostField.getText().trim();
        int parsedPort;
        try {
            parsedPort = Integer.parseInt(targetPortField.getText().trim());
        } catch (NumberFormatException e) {
            parsedPort = tlsCheck.isSelected() ? 443 : 80;
        }

        final String targetHost = host;
        final int targetPort = parsedPort;
        final boolean useTls = tlsCheck.isSelected();
        final CollaboratorClient client = collabClient;
        final String smuggledPath = smuggledPathField.getText().trim();
        final String followupPath = followupPathField.getText().trim();

        List<Hypothesis> hyps = generator.generate(max);

        new SwingWorker<Void, Object[]>() {
            @Override
            protected Void doInBackground() {
                // Fingerprint the follow-up and smuggled resources once, so the
                // classifier can catch "quiet 200/200" queue poisons by identity.
                DesyncReplayer.Baseline baseline =
                        replayer.buildBaseline(targetHost, targetPort, useTls, smuggledPath, followupPath);
                api.logging().logToOutput("[identity] baseline: followup=" + sigInfo(baseline == null ? null : baseline.followupSig)
                        + " smuggled=" + sigInfo(baseline == null ? null : baseline.smuggledSig));

                for (Hypothesis hyp : hyps) {
                    if ("h2".equals(hyp.nativeEngine)) {
                        publish(new Object[]{hyp.id, hyp.category, hyp.expect, "skipped", "-", "-", "-"});
                        continue;
                    }
                    ClassifyResult result = replayer.replay(hyp, targetHost, targetPort, useTls, baseline);
                    publish(new Object[]{
                            hyp.id, hyp.category, hyp.expect, result.verdict,
                            result.firstStatus, result.followupStatus, result.elapsedMs
                    });
                }
                if (client != null) {
                    pollOob(client);
                }
                return null;
            }

            @Override
            protected void process(List<Object[]> chunks) {
                for (Object[] row : chunks) {
                    tableModel.addRow(row);
                }
            }

            @Override
            protected void done() {
                runButton.setEnabled(true);
            }
        }.execute();
    }

    /**
     * After the replay run, poll this scan's dedicated Collaborator client for
     * out-of-band callbacks triggered by the absolute-form authority. An HTTP fetch
     * (ideally of the probe path) is strong proof of front-end routing confusion /
     * SSRF -> "oob-confirmed"; a bare DNS lookup is weaker -> "oob-dns". Every
     * interaction is logged with type, source IP and path/token so it can be
     * verified independently (the extension's client is separate from the
     * interactive Collaborator tab, so these never show up there).
     */
    private void pollOob(CollaboratorClient client) {
        for (int i = 0; i < 6; i++) {
            try {
                Thread.sleep(2000);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return;
            }
            List<Interaction> hits;
            try {
                hits = client.getAllInteractions();
            } catch (Exception e) {
                continue;
            }
            if (hits.isEmpty()) {
                continue;
            }

            Interaction http = null;
            Interaction dns = null;
            for (Interaction it : hits) {
                String src = it.clientIp() != null ? it.clientIp().getHostAddress() : "?";
                if (it.type() == InteractionType.HTTP) {
                    String path = "?";
                    if (it.httpDetails().isPresent()) {
                        try {
                            path = it.httpDetails().get().requestResponse().request().path();
                        } catch (Exception ignored) {
                        }
                    }
                    api.logging().logToOutput("[OOB] HTTP callback from " + src + ":" + it.clientPort()
                            + " path=" + path + " id=" + it.id());
                    // Prefer a callback that carries the probe path, but any HTTP fetch is strong.
                    if (http == null || (path.contains(OOB_PROBE_PATH) && !isProbePath(http))) {
                        http = it;
                    }
                } else if (it.type() == InteractionType.DNS) {
                    String q = it.dnsDetails().isPresent() ? it.dnsDetails().get().queryType().toString() : "?";
                    api.logging().logToOutput("[OOB] DNS lookup from " + src + " query=" + q + " id=" + it.id());
                    if (dns == null) {
                        dns = it;
                    }
                } else {
                    api.logging().logToOutput("[OOB] " + it.type() + " interaction from " + src + " id=" + it.id());
                }
            }

            if (http != null) {
                String src = http.clientIp() != null ? http.clientIp().getHostAddress() : "?";
                api.logging().logToOutput("[OOB] OOB-CONFIRMED routing confusion / SSRF — front-end fetched the "
                        + "absolute-form authority (HTTP callback from " + src + ")");
                SwingUtilities.invokeLater(() -> markOob("oob-confirmed"));
                return;
            }
            if (dns != null) {
                api.logging().logToOutput("[OOB] weak signal: DNS-only lookup of the OOB authority (no HTTP fetch) — "
                        + "verify manually before trusting");
                SwingUtilities.invokeLater(() -> markOob("oob-dns"));
                return;
            }
        }
        api.logging().logToOutput("[OOB] no Collaborator interactions for absolute-form SSRF probe");
    }

    private String sigInfo(DesyncReplayer.Sig sig) {
        return sig == null ? "n/a" : sig.toString();
    }

    private boolean isProbePath(Interaction it) {
        if (it.httpDetails().isEmpty()) {
            return false;
        }
        try {
            return it.httpDetails().get().requestResponse().request().path().contains(OOB_PROBE_PATH);
        } catch (Exception e) {
            return false;
        }
    }

    private void markOob(String verdict) {
        for (int r = 0; r < tableModel.getRowCount(); r++) {
            Object id = tableModel.getValueAt(r, 0);
            if (id != null && id.toString().startsWith(OOB_ID_PREFIX)) {
                tableModel.setValueAt(verdict, r, VERDICT_COLUMN);
            }
        }
    }
}
