package com.blurpsuite;

import com.blurpsuite.api.BurpExtenderCallbacksImpl;
import com.blurpsuite.core.ProxyServer;
import com.blurpsuite.extensions.ExtensionManager;
import com.blurpsuite.ui.MainWindow;

import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

/** Entry point for the Blurp Suite desktop application and headless proxy. */
public final class Main {
    private static final String VERSION = "1.0.0";

    private Main() {
    }

    public static void main(String[] args) throws Exception {
        Options options = Options.parse(args);
        if (options.help) {
            printUsage(System.out);
            return;
        }
        if (options.version) {
            System.out.println("Blurp Suite " + VERSION);
            return;
        }

        JTextArea console = new JTextArea();
        PrintStream stdout = new TeePrintStream(System.out, console);
        PrintStream stderr = new TeePrintStream(System.err, console);

        ProxyServer proxy = new ProxyServer(options.port, options.bindAddress);
        ExtensionManager extensions = new ExtensionManager(proxy,
                options.extensionArguments.toArray(String[]::new), stdout, stderr);
        extensions.setPythonHome(options.pythonHome);
        extensions.setPythonExecutable(options.pythonExecutable);

        // Install this before startup: a shutdown signal can arrive as soon as
        // the proxy announces that it is listening.
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                extensions.unloadAll();
            } finally {
                proxy.stop();
            }
        }, "blurp-shutdown"));

        for (Path extension : options.extensions) {
            try {
                loadExtension(extensions, extension);
            } catch (Exception e) {
                stderr.println("Could not load extension " + extension + ": " + e);
            }
        }

        proxy.start();
        stdout.printf("Blurp Suite %s listening on %s:%d%n",
                VERSION, options.bindAddress, options.port);

        if (options.headless) {
            stdout.println("Headless mode: press Ctrl+C to stop.");
            new CountDownLatch(1).await();
            return;
        }

        SwingUtilities.invokeAndWait(() -> {
            MainWindow window = new MainWindow(proxy, extensions, console, stdout, stderr);
            List<BurpExtenderCallbacksImpl> callbacks = extensions.list().stream()
                    .map(ExtensionManager.LoadedExtension::callbacks)
                    .toList();
            window.addExtensionTabs(callbacks);
            window.setVisible(true);
        });
    }

    private static void loadExtension(ExtensionManager manager, Path path) throws Exception {
        String name = path.getFileName().toString().toLowerCase(java.util.Locale.ROOT);
        if (name.endsWith(".py")) {
            manager.loadPython(path);
        } else {
            manager.loadJava(path);
        }
    }

    private static void printUsage(PrintStream out) {
        out.println("Usage: blurpsuite [options]");
        out.println();
        out.println("Options:");
        out.println("  --port <port>            Proxy listen port (default: 8080)");
        out.println("  --bind <address>         Bind address (default: 127.0.0.1)");
        out.println("  --extension <path>       Load a Java JAR/classes directory or Python .py file");
        out.println("                           (repeatable)");
        out.println("  --python-home <path>     Python bridge package root (default: python)");
        out.println("  --python <executable>    Python executable (default: python3)");
        out.println("  --headless               Run without the Swing UI");
        out.println("  --extension-arg <value>  Pass a value to extensions (repeatable)");
        out.println("  --version                Print version and exit");
        out.println("  --help                   Show this help");
    }

    private static final class Options {
        int port = 8080;
        String bindAddress = "127.0.0.1";
        Path pythonHome = Path.of("python");
        String pythonExecutable = "python3";
        boolean headless;
        boolean help;
        boolean version;
        final List<Path> extensions = new ArrayList<>();
        final List<String> extensionArguments = new ArrayList<>();

        static Options parse(String[] args) {
            Options options = new Options();
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                switch (arg) {
                    case "--help", "-h" -> options.help = true;
                    case "--version", "-V" -> options.version = true;
                    case "--headless" -> options.headless = true;
                    case "--port" -> options.port = Integer.parseInt(requireValue(args, ++i, arg));
                    case "--bind" -> options.bindAddress = requireValue(args, ++i, arg);
                    case "--extension", "-e" -> options.extensions.add(
                            Path.of(requireValue(args, ++i, arg)));
                    case "--python-home" -> options.pythonHome =
                            Path.of(requireValue(args, ++i, arg));
                    case "--python" -> options.pythonExecutable = requireValue(args, ++i, arg);
                    case "--extension-arg" -> options.extensionArguments.add(
                            requireValue(args, ++i, arg));
                    default -> throw new IllegalArgumentException("Unknown option: " + arg);
                }
            }
            return options;
        }

        private static String requireValue(String[] args, int index, String option) {
            if (index >= args.length) {
                throw new IllegalArgumentException("Missing value for " + option);
            }
            return args[index];
        }
    }

    /** Writes extension output to both the original stream and the UI console. */
    private static final class TeePrintStream extends PrintStream {
        private final JTextArea console;

        TeePrintStream(PrintStream delegate, JTextArea console) {
            super(delegate, true);
            this.console = console;
        }

        @Override
        public void write(int b) {
            super.write(b);
            appendConsole(String.valueOf((char) b));
        }

        @Override
        public void write(byte[] buffer, int offset, int length) {
            super.write(buffer, offset, length);
            appendConsole(new String(buffer, offset, length));
        }

        private void appendConsole(String text) {
            SwingUtilities.invokeLater(() -> {
                console.append(text);
                console.setCaretPosition(console.getDocument().getLength());
            });
        }
    }
}
