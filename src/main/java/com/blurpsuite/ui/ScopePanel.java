package com.blurpsuite.ui;

import com.blurpsuite.core.ProxyServer;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.net.URL;

/** Editor for the ordered target scope rules. */
public final class ScopePanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private final transient ProxyServer proxy;
    private final DefaultListModel<String> includes = new DefaultListModel<>();
    private final DefaultListModel<String> excludes = new DefaultListModel<>();
    private final JList<String> includeList = new JList<>(includes);
    private final JList<String> excludeList = new JList<>(excludes);

    public ScopePanel(ProxyServer proxy) {
        this.proxy = proxy;
        setLayout(new BorderLayout(12, 12));
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
        reload();

        JPanel lists = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.weightx = 1;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;
        c.gridx = 0;
        c.gridy = 0;
        lists.add(ruleList("Include rules", includeList,
                e -> addRule(true), e -> removeRule(true)), c);
        c.gridx = 1;
        lists.add(ruleList("Exclude rules", excludeList,
                e -> addRule(false), e -> removeRule(false)), c);

        add(new JLabel("<html>Include rules limit which targets the proxy will forward. "
                + "Exclude rules always win. A hostname, wildcard hostname or URL prefix is accepted.</html>"),
                BorderLayout.NORTH);
        add(lists, BorderLayout.CENTER);
    }

    private static JPanel ruleList(String title, JList<String> list,
                                   java.awt.event.ActionListener add,
                                   java.awt.event.ActionListener remove) {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setBorder(BorderFactory.createTitledBorder(title));
        panel.add(new JScrollPane(list), BorderLayout.CENTER);
        JPanel buttons = new JPanel();
        JButton addButton = new JButton("Add");
        JButton removeButton = new JButton("Remove");
        addButton.addActionListener(add);
        removeButton.addActionListener(remove);
        buttons.add(addButton);
        buttons.add(removeButton);
        panel.add(buttons, BorderLayout.SOUTH);
        return panel;
    }

    private void addRule(boolean include) {
        String value = JOptionPane.showInputDialog(this,
                include ? "Hostname or URL prefix to include:" : "Hostname or URL prefix to exclude:",
                "Target scope", JOptionPane.QUESTION_MESSAGE);
        if (value == null || value.isBlank()) {
            return;
        }
        if (include) {
            proxy.scope().include(value);
        } else {
            proxy.scope().exclude(value);
        }
        reload();
    }

    private void removeRule(boolean include) {
        JList<String> list = include ? includeList : excludeList;
        String selected = list.getSelectedValue();
        if (selected == null) {
            return;
        }
        if (include) {
            proxy.scope().removeInclude(selected);
        } else {
            proxy.scope().removeExclude(selected);
        }
        reload();
    }

    private void reload() {
        includes.clear();
        excludes.clear();
        for (String rule : proxy.scope().includes()) {
            includes.addElement(rule);
        }
        for (String rule : proxy.scope().excludes()) {
            excludes.addElement(rule);
        }
    }

    /** Returns true when a URL would currently be proxied. */
    public boolean isInScope(String url) {
        try {
            return proxy.scope().isInScope(new URL(url));
        } catch (Exception e) {
            return false;
        }
    }
}
