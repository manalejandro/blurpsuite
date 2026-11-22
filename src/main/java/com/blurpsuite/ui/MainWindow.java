package com.blurpsuite.ui;

import burp.ITab;
import com.blurpsuite.api.BurpExtenderCallbacksImpl;
import com.blurpsuite.core.ProxyServer;
import com.blurpsuite.extensions.ExtensionManager;

import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.io.PrintStream;
import java.util.HashSet;
import java.util.Set;

/** Main application window. */
public final class MainWindow extends JFrame implements TabHost {
    private static final long serialVersionUID = 1L;

    private final JTabbedPane tabs = new JTabbedPane();
    private final transient Set<Component> extensionTabs = new HashSet<>();
    private final DashboardPanel dashboard;
    private final InterceptPanel intercept;

    public MainWindow(ProxyServer proxy, ExtensionManager extensions, JTextArea consoleArea,
                      PrintStream stdout, PrintStream stderr) {
        super("Blurp Suite 1.0.0");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(1024, 700));
        setSize(1280, 820);
        setLocationRelativeTo(null);

        consoleArea.setEditable(false);
        consoleArea.setLineWrap(true);
        consoleArea.setWrapStyleWord(true);
        consoleArea.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 12));

        dashboard = new DashboardPanel(proxy, extensions);
        intercept = new InterceptPanel(proxy);
        HistoryPanel history = new HistoryPanel(proxy);
        ScopePanel scope = new ScopePanel(proxy);
        ExtensionsPanel extensionPanel = new ExtensionsPanel(extensions, this,
                stdout, stderr, consoleArea);

        tabs.addTab("Dashboard", dashboard);
        tabs.addTab("Intercept", intercept);
        tabs.addTab("HTTP history", history);
        tabs.addTab("Target scope", scope);
        tabs.addTab("Extensions", extensionPanel);
        tabs.addTab("Output", new JScrollPane(consoleArea));
        add(tabs, BorderLayout.CENTER);
        setJMenuBar(menuBar());
    }

    private JMenuBar menuBar() {
        JMenuBar bar = new JMenuBar();
        JMenu file = new JMenu("File");
        JMenuItem exit = new JMenuItem("Exit");
        exit.addActionListener(e -> dispose());
        file.add(exit);
        JMenu help = new JMenu("Help");
        JMenuItem about = new JMenuItem("About Blurp Suite");
        about.addActionListener(e -> JOptionPane.showMessageDialog(this,
                "Blurp Suite 1.0.0\n\nAn independent, API-compatible HTTP interception proxy "
                        + "with Java and Python extension support.\n"
                        + "Not affiliated with PortSwigger.",
                "About", JOptionPane.INFORMATION_MESSAGE));
        help.add(about);
        bar.add(file);
        bar.add(help);
        return bar;
    }

    @Override
    public void addExtensionTab(ITab tab) {
        if (tab == null || tab.getUiComponent() == null || extensionTabs.contains(tab.getUiComponent())) {
            return;
        }
        Component component = tab.getUiComponent();
        extensionTabs.add(component);
        SwingUtilities.invokeLater(() -> tabs.addTab(tab.getTabCaption(), component));
    }

    /** Refreshes panels whose state can be changed from the CLI or an extension. */
    public void refreshState() {
        dashboard.externalStateChanged();
        intercept.refreshInterceptionState();
    }

    /** Adds custom tabs contributed by extensions already loaded at startup. */
    public void addExtensionTabs(Iterable<BurpExtenderCallbacksImpl> callbacksList) {
        for (BurpExtenderCallbacksImpl callbacks : callbacksList) {
            for (ITab tab : callbacks.suiteTabs()) {
                addExtensionTab(tab);
            }
        }
    }
}
