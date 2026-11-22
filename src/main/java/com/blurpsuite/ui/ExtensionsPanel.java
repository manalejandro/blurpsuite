package com.blurpsuite.ui;

import burp.ITab;
import com.blurpsuite.extensions.ExtensionManager;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.Timer;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.io.PrintStream;
import java.nio.file.Path;

/** Extension manager panel with a live output console. */
public final class ExtensionsPanel extends JPanel {
    private static final long serialVersionUID = 1L;
    private static final String[] COLUMNS = {"Name", "Language", "Path", "Status"};

    private final transient ExtensionManager manager;
    private final transient TabHost tabHost;
    private final transient PrintStream stdout;
    private final transient PrintStream stderr;
    private final DefaultTableModel model = new DefaultTableModel(COLUMNS, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private final JTable table = new JTable(model);
    private final JTextArea console;

    public ExtensionsPanel(ExtensionManager manager, TabHost tabHost,
                           PrintStream stdout, PrintStream stderr, JTextArea console) {
        this.manager = manager;
        this.tabHost = tabHost;
        this.stdout = stdout;
        this.stderr = stderr;
        this.console = console;
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton loadJava = new JButton("Load Java extension");
        JButton loadPython = new JButton("Load Python extension");
        JButton unload = new JButton("Unload selected");
        actions.add(loadJava);
        actions.add(loadPython);
        actions.add(unload);
        actions.add(new JLabel("<html>Extensions run with the Blurp <code>burp.*</code> API.</html>"));

        table.setRowHeight(22);
        table.getColumnModel().getColumn(2).setPreferredWidth(360);
        console.setEditable(false);
        console.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), new JScrollPane(console));
        split.setResizeWeight(0.4);
        add(actions, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        loadJava.addActionListener(e -> load(true));
        loadPython.addActionListener(e -> load(false));
        unload.addActionListener(e -> unloadSelected());
        new Timer(1000, e -> refresh()).start();
        refresh();
    }

    private void load(boolean java) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle(java ? "Select a Java extension" : "Select a Python extension");
        chooser.setFileFilter(java
                ? new FileNameExtensionFilter("Java extensions", "jar", "class")
                : new FileNameExtensionFilter("Python extensions", "py"));
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path path = chooser.getSelectedFile().toPath();
        try {
            ExtensionManager.LoadedExtension extension = java
                    ? manager.loadJava(path) : manager.loadPython(path);
            for (ITab tab : extension.callbacks().suiteTabs()) {
                tabHost.addExtensionTab(tab);
            }
            stdout.println("[ui] loaded " + extension.type() + " extension '"
                    + extension.name() + "'");
        } catch (Exception e) {
            stderr.println("[ui] failed to load " + path + ": " + e);
            JOptionPane.showMessageDialog(this, "Cannot load extension:\n" + e.getMessage(),
                    "Blurp Suite", JOptionPane.ERROR_MESSAGE);
        }
        refresh();
    }

    private void unloadSelected() {
        int row = table.getSelectedRow();
        if (row < 0) {
            return;
        }
        String name = String.valueOf(model.getValueAt(row, 0));
        if (!manager.unload(name)) {
            JOptionPane.showMessageDialog(this, "Extension was already unloaded.",
                    "Blurp Suite", JOptionPane.INFORMATION_MESSAGE);
        }
        refresh();
    }

    private void refresh() {
        model.setRowCount(0);
        for (ExtensionManager.LoadedExtension extension : manager.list()) {
            model.addRow(new Object[]{extension.name(), extension.type(),
                    extension.path().toAbsolutePath(), extension.isUnloaded() ? "Unloaded" : "Active"});
        }
    }
}
