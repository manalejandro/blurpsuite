package com.blurpsuite.ui;

import com.blurpsuite.core.ProxyServer;
import com.blurpsuite.extensions.ExtensionManager;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

/** Home panel with proxy controls and live counters. */
public final class DashboardPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private final transient ProxyServer proxy;
    private final transient ExtensionManager extensions;
    private final JTextField bindField = new JTextField("127.0.0.1", 16);
    private final JLabel status = new JLabel("Stopped");
    private final JLabel historyCount = new JLabel("0");
    private final JLabel queuedCount = new JLabel("0");
    private final JLabel extensionCount = new JLabel("0");
    private final JLabel scopeSummary = new JLabel("All targets");
    private final JCheckBox interceptBox = new JCheckBox("Intercept requests and responses");
    private final JButton toggle = new JButton("Start proxy");

    public DashboardPanel(ProxyServer proxy, ExtensionManager extensions) {
        this.proxy = proxy;
        this.extensions = extensions;
        bindField.setText(proxy.bindAddress());
        setLayout(new BorderLayout(16, 16));
        setBorder(BorderFactory.createEmptyBorder(20, 24, 24, 24));

        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        JLabel title = new JLabel("Blurp Suite");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 28f));
        JLabel subtitle = new JLabel("Intercepting HTTP proxy with Java and Python extensions");
        subtitle.setForeground(new java.awt.Color(90, 98, 110));
        header.add(title);
        header.add(subtitle);
        add(header, BorderLayout.NORTH);

        JPanel card = new JPanel(new GridBagLayout());
        card.setBorder(BorderFactory.createTitledBorder("Proxy"));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6, 6, 6, 6);
        c.anchor = GridBagConstraints.WEST;
        c.gridx = 0;
        c.gridy = 0;
        card.add(new JLabel("Bind address"), c);
        c.gridx = 1;
        card.add(bindField, c);
        c.gridx = 0;
        c.gridy = 1;
        card.add(new JLabel("Port"), c);
        c.gridx = 1;
        card.add(new JLabel(String.valueOf(proxy.port())), c);
        c.gridx = 0;
        c.gridy = 2;
        card.add(new JLabel("Status"), c);
        c.gridx = 1;
        status.setFont(status.getFont().deriveFont(Font.BOLD));
        card.add(status, c);
        c.gridx = 2;
        c.gridy = 0;
        c.gridheight = 3;
        card.add(toggle, c);
        c.gridheight = 1;
        c.gridx = 0;
        c.gridy = 3;
        c.gridwidth = 3;
        card.add(interceptBox, c);

        JPanel stats = new JPanel(new GridBagLayout());
        stats.setBorder(BorderFactory.createTitledBorder("Live status"));
        addStat(stats, 0, "HTTP history", historyCount);
        addStat(stats, 1, "Queued interceptions", queuedCount);
        addStat(stats, 2, "Loaded extensions", extensionCount);
        addStat(stats, 3, "Scope", scopeSummary);

        JPanel center = new JPanel(new GridBagLayout());
        GridBagConstraints cc = new GridBagConstraints();
        cc.weightx = 1;
        cc.fill = GridBagConstraints.HORIZONTAL;
        cc.insets = new Insets(0, 0, 12, 0);
        cc.gridy = 0;
        center.add(card, cc);
        cc.gridy = 1;
        center.add(stats, cc);
        add(center, BorderLayout.CENTER);

        JPanel help = new JPanel();
        help.add(new JLabel("<html>Point a browser or client at <b>http://"
                + "127.0.0.1:" + proxy.port() + "</b> as its HTTP proxy. "
                + "HTTPS CONNECT tunnels are passed through without interception.</html>"));
        add(help, BorderLayout.SOUTH);

        toggle.addActionListener(e -> toggleProxy());
        interceptBox.addActionListener(e -> proxy.setInterceptionEnabled(interceptBox.isSelected()));
        new Timer(800, e -> refresh()).start();
        refresh();
    }

    private static void addStat(JPanel panel, int row, String label, JLabel value) {
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(5, 8, 5, 8);
        c.anchor = GridBagConstraints.WEST;
        c.gridy = row;
        c.gridx = 0;
        panel.add(new JLabel(label), c);
        c.gridx = 1;
        c.weightx = 1;
        panel.add(value, c);
    }

    private void toggleProxy() {
        if (proxy.isRunning()) {
            proxy.stop();
        } else {
            String bind = bindField.getText().trim();
            if (bind.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Enter a bind address.", "Blurp Suite",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }
            bindField.setEnabled(false);
            try {
                proxy.setBindAddress(bind);
                proxy.start();
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Cannot start proxy: " + e.getMessage(),
                        "Blurp Suite", JOptionPane.ERROR_MESSAGE);
                bindField.setEnabled(true);
            }
        }
        refresh();
    }

    private void refresh() {
        SwingUtilities.invokeLater(() -> {
            boolean running = proxy.isRunning();
            status.setText(running ? "Listening on " + proxy.port() : "Stopped");
            status.setForeground(running ? new java.awt.Color(24, 128, 72)
                    : new java.awt.Color(170, 60, 60));
            toggle.setText(running ? "Stop proxy" : "Start proxy");
            bindField.setEnabled(!running);
            interceptBox.setSelected(proxy.isInterceptionEnabled());
            historyCount.setText(String.valueOf(proxy.history().size()));
            queuedCount.setText(String.valueOf(proxy.queuedInterceptions()));
            extensionCount.setText(String.valueOf(extensions.list().size()));
            var includes = proxy.scope().includes();
            var excludes = proxy.scope().excludes();
            scopeSummary.setText(includes.isEmpty() && excludes.isEmpty()
                    ? "All targets"
                    : includes.size() + " include / " + excludes.size() + " exclude");
        });
    }

    /** Used by the CLI to reflect an externally started proxy. */
    public void externalStateChanged() {
        refresh();
    }
}
