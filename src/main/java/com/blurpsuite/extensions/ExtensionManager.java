package com.blurpsuite.extensions;

import com.blurpsuite.api.ApiTrafficBridge;
import com.blurpsuite.api.BurpExtenderCallbacksImpl;
import com.blurpsuite.core.ProxyServer;
import com.blurpsuite.core.TrafficListener;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** Registers, tracks and unloads Java and Python extensions. */
public final class ExtensionManager {
    private final ProxyServer proxy;
    private final String[] commandLineArguments;
    private final PrintStream stdout;
    private final PrintStream stderr;
    private final List<LoadedExtension> extensions = new ArrayList<>();
    private Path pythonHome = Path.of("python");
    private String pythonExecutable = "python3";

    public ExtensionManager(ProxyServer proxy, String[] commandLineArguments,
                            PrintStream stdout, PrintStream stderr) {
        this.proxy = proxy;
        this.commandLineArguments = commandLineArguments.clone();
        this.stdout = stdout;
        this.stderr = stderr;
    }

    public void setPythonHome(Path path) {
        this.pythonHome = path;
    }

    public void setPythonExecutable(String executable) {
        this.pythonExecutable = executable;
    }

    /** Loads a Java extension from a JAR, a class directory or a single class file. */
    public synchronized LoadedExtension loadJava(Path artifact) throws Exception {
        if (!Files.exists(artifact)) {
            throw new IOException("Extension not found: " + artifact);
        }
        BurpExtenderCallbacksImpl callbacks = newCallbacks(artifact);
        JavaExtensionLoader.LoadedJavaExtension loaded =
                JavaExtensionLoader.load(artifact, callbacks);
        String name = callbacks.extensionName();
        LoadedExtension entry = new LoadedExtension(proxy, name, artifact, "java", callbacks);
        entry.javaExtension = loaded;
        entry.trafficBridge = bindTraffic(callbacks);
        extensions.add(entry);
        stdout.println("[extensions] loaded Java extension '" + name + "' from " + artifact);
        return entry;
    }

    /** Loads a Python extension by starting its bridge process. */
    public synchronized LoadedExtension loadPython(Path script) throws Exception {
        if (!Files.exists(script)) {
            throw new IOException("Extension not found: " + script);
        }
        BurpExtenderCallbacksImpl callbacks = newCallbacks(script);
        PythonExtensionHost host = new PythonExtensionHost(callbacks, script, pythonHome,
                pythonExecutable);
        // Extension-initiated unloads must go through the manager so the proxy
        // listener and loaded-extension entry are removed as well. The work is
        // asynchronous because this handler runs on the JSON-RPC reader thread,
        // which must stay free to read the child's replies.
        callbacks.setUnloadAction(() -> unloadAsync(host));
        String name = host.initialize();
        LoadedExtension entry = new LoadedExtension(proxy, name, script, "python", callbacks);
        entry.pythonHost = host;
        // Python listeners live in the child process, so the host itself is the traffic bridge.
        proxy.addListener(host);
        entry.trafficBridge = host;
        extensions.add(entry);
        stdout.println("[extensions] loaded Python extension '" + name + "' from " + script);
        return entry;
    }

    private BurpExtenderCallbacksImpl newCallbacks(Path artifact) {
        BurpExtenderCallbacksImpl callbacks = new BurpExtenderCallbacksImpl(proxy,
                commandLineArguments, stdout, stderr);
        callbacks.setExtensionFilename(artifact.getFileName().toString());
        return callbacks;
    }

    private ApiTrafficBridge bindTraffic(BurpExtenderCallbacksImpl callbacks) {
        ApiTrafficBridge bridge = new ApiTrafficBridge(callbacks);
        proxy.addListener(bridge);
        return bridge;
    }

    public synchronized boolean unload(String name) {
        for (int i = 0; i < extensions.size(); i++) {
            LoadedExtension entry = extensions.get(i);
            if (entry.name.equalsIgnoreCase(name) || entry.path.toString().equals(name)) {
                entry.close();
                extensions.remove(i);
                stdout.println("[extensions] unloaded '" + entry.name + "'");
                return true;
            }
        }
        return false;
    }

    /** Starts an unload on a separate thread, safe from a JSON-RPC callback. */
    private void unloadAsync(PythonExtensionHost host) {
        Thread unloader = new Thread(() -> unload(host), "blurp-python-unload");
        unloader.setDaemon(true);
        unloader.start();
    }

    /** Unloads the loaded extension that owns the given Python host. */
    private synchronized boolean unload(PythonExtensionHost host) {
        for (LoadedExtension entry : extensions) {
            if (entry.pythonHost == host) {
                return unload(entry.name);
            }
        }
        return false;
    }

    public synchronized void unloadAll() {
        for (LoadedExtension entry : extensions) {
            entry.close();
        }
        extensions.clear();
    }

    public synchronized List<LoadedExtension> list() {
        return Collections.unmodifiableList(new ArrayList<>(extensions));
    }

    /** Describes one loaded extension. */
    public static final class LoadedExtension {
        private final String name;
        private final Path path;
        private final String type;
        private final BurpExtenderCallbacksImpl callbacks;
        private final ProxyServer proxyRef;
        private TrafficListener trafficBridge;
        private JavaExtensionLoader.LoadedJavaExtension javaExtension;
        private PythonExtensionHost pythonHost;
        private volatile boolean unloaded;

        LoadedExtension(ProxyServer proxy, String name, Path path, String type,
                        BurpExtenderCallbacksImpl callbacks) {
            this.proxyRef = proxy;
            this.name = name;
            this.path = path;
            this.type = type;
            this.callbacks = callbacks;
        }

        public String name() {
            return name;
        }

        public Path path() {
            return path;
        }

        public String type() {
            return type;
        }

        public BurpExtenderCallbacksImpl callbacks() {
            return callbacks;
        }

        public boolean isUnloaded() {
            return unloaded;
        }

        synchronized void close() {
            if (unloaded) {
                return;
            }
            unloaded = true;
            try {
                callbacks.notifyExtensionStateListeners();
            } finally {
                if (trafficBridge != null) {
                    proxyRef.removeListener(trafficBridge);
                }
                if (javaExtension != null) {
                    try {
                        javaExtension.close();
                    } catch (IOException ignored) {
                        // Best effort.
                    }
                }
                if (pythonHost != null) {
                    pythonHost.close();
                }
                callbacks.dispose();
            }
        }

    }
}
