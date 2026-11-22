package com.blurpsuite.ui;

import com.blurpsuite.core.ProxyServer;
import com.blurpsuite.util.ByteUtil;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Insets;
import java.util.concurrent.TimeUnit;

/** Shows messages paused by manual interception and forwards or drops them. */
public final class InterceptPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private final transient ProxyServer proxy;
    private final JTextArea requestArea = new JTextArea();
    private final JTextArea responseArea = new JTextArea();
    private final JLabel details = new JLabel("No message intercepted");
    private final JCheckBox interceptBox = new JCheckBox("Intercept on");
    private final JButton apply = new JButton("Apply edits");
    private final JButton forward = new JButton("Forward");
    private final JButton drop = new JButton("Drop");
    private transient volatile ProxyServer.Interception current;

    public InterceptPanel(ProxyServer proxy) {
        this.proxy = proxy;
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        interceptBox.setSelected(proxy.isInterceptionEnabled());
        interceptBox.addActionListener(e -> proxy.setInterceptionEnabled(interceptBox.isSelected()));
        top.add(interceptBox);
        top.add(details);
        add(top, BorderLayout.NORTH);

        requestArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        requestArea.setEditable(true);
        responseArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        responseArea.setEditable(true);
        JTabbedPane messages = new JTabbedPane();
        messages.addTab("Request", new javax.swing.JScrollPane(requestArea));
        messages.addTab("Response", new javax.swing.JScrollPane(responseArea));

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        apply.setMnemonic('A');
        forward.setMnemonic('F');
        drop.setMnemonic('D');
        actions.add(apply);
        actions.add(drop);
        actions.add(forward);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, messages, actions);
        split.setResizeWeight(1);
        split.setDividerSize(4);
        add(split, BorderLayout.CENTER);

        apply.addActionListener(e -> applyEdits());
        forward.addActionListener(e -> resolve(false));
        drop.addActionListener(e -> resolve(true));
        setButtons(false);

        new Timer(150, e -> poll()).start();
    }

    private void poll() {
        ProxyServer.Interception pending = current;
        if (pending == null) {
            try {
                pending = proxy.pollInterception(0, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            if (pending != null) {
                current = pending;
                show(pending);
            }
        }
        if (current != null && !interceptBox.isSelected()) {
            resolve(false);
        }
    }

    private void show(ProxyServer.Interception pending) {
        var exchange = pending.exchange();
        String kind = pending.isRequest() ? "Request" : "Response";
        details.setText(kind + " #" + exchange.reference() + " from " + exchange.clientAddress());
        if (pending.isRequest()) {
            UiSupport.setTextLater(requestArea, UiSupport.messageText(exchange.getRequest()));
            UiSupport.setTextLater(responseArea, "");
        } else {
            UiSupport.setTextLater(responseArea, UiSupport.messageText(exchange.getResponse()));
        }
        setButtons(true);
    }

    private void applyEdits() {
        ProxyServer.Interception pending = current;
        if (pending == null) {
            return;
        }
        if (pending.isRequest()) {
            pending.exchange().setRequest(ByteUtil.toBytes(requestArea.getText()));
        } else {
            pending.exchange().setResponse(ByteUtil.toBytes(responseArea.getText()));
        }
    }

    private void resolve(boolean shouldDrop) {
        ProxyServer.Interception pending = current;
        if (pending == null) {
            return;
        }
        current = null;
        pending.resolve(shouldDrop);
        SwingUtilities.invokeLater(() -> {
            requestArea.setText("");
            responseArea.setText("");
            details.setText("No message intercepted");
            setButtons(false);
        });
    }

    private void setButtons(boolean enabled) {
        apply.setEnabled(enabled);
        forward.setEnabled(enabled);
        drop.setEnabled(enabled);
    }

    /** Keeps the checkbox in sync when interception is toggled from another panel. */
    public void refreshInterceptionState() {
        interceptBox.setSelected(proxy.isInterceptionEnabled());
    }
}
