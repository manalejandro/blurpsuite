package com.blurpsuite.api;

import burp.IBurpCollaboratorClientContext;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.ICookie;
import burp.IExtensionHelpers;
import burp.IExtensionStateListener;
import burp.IHttpHeader;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponsePersisted;
import burp.IHttpRequestResponseWithMarkers;
import burp.IHttpService;
import burp.IInterceptedProxyMessage;
import burp.IIntruderAttack;
import burp.IIntruderPayloadGeneratorFactory;
import burp.IIntruderPayloadProcessor;
import burp.IMenuItemHandler;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IMessageEditorTabFactory;
import burp.IParameter;
import burp.IProxyListener;
import burp.IScanIssue;
import burp.IScanQueueItem;
import burp.IScannerCheck;
import burp.IScannerInsertionPointProvider;
import burp.IScannerListener;
import burp.IScopeChangeListener;
import burp.ISessionHandlingAction;
import burp.ITab;
import burp.ITempFile;
import burp.ITextEditor;
import com.blurpsuite.core.HttpExchange;
import com.blurpsuite.core.HttpParser;
import com.blurpsuite.core.ProxyServer;
import com.blurpsuite.core.Scope;
import com.blurpsuite.core.Service;
import com.blurpsuite.util.Json;
import com.blurpsuite.util.ByteUtil;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

/** Implementation of the callback surface exposed to loaded extensions. */
public final class BurpExtenderCallbacksImpl implements IBurpExtenderCallbacks {
    private final ProxyServer proxy;
    private final ExtensionHelpersImpl helpers = new ExtensionHelpersImpl();
    private final AtomicReference<String> extensionName = new AtomicReference<>("Unnamed extension");
    private final List<IProxyListener> proxyListeners = new CopyOnWriteArrayList<>();
    private final List<IHttpListener> httpListeners = new CopyOnWriteArrayList<>();
    private final List<IScopeChangeListener> scopeListeners = new CopyOnWriteArrayList<>();
    private final List<IExtensionStateListener> stateListeners = new CopyOnWriteArrayList<>();
    private final List<IContextMenuFactory> contextMenuFactories = new CopyOnWriteArrayList<>();
    private final List<IMessageEditorTabFactory> messageEditorTabFactories = new CopyOnWriteArrayList<>();
    private final List<IIntruderPayloadGeneratorFactory> payloadGeneratorFactories = new CopyOnWriteArrayList<>();
    private final List<IIntruderPayloadProcessor> payloadProcessors = new CopyOnWriteArrayList<>();
    private final List<IScannerCheck> scannerChecks = new CopyOnWriteArrayList<>();
    private final List<IScannerInsertionPointProvider> insertionPointProviders = new CopyOnWriteArrayList<>();
    private final List<IScannerListener> scannerListeners = new CopyOnWriteArrayList<>();
    private final List<ISessionHandlingAction> sessionHandlingActions = new CopyOnWriteArrayList<>();
    private final List<ITab> suiteTabs = new CopyOnWriteArrayList<>();
    private final List<IHttpRequestResponse> siteMap = new CopyOnWriteArrayList<>();
    private final List<IScanIssue> scanIssues = new CopyOnWriteArrayList<>();
    private final List<ICookie> cookieJar = new CopyOnWriteArrayList<>();
    private final Map<String, String> settings = new LinkedHashMap<>();
    private final Map<String, IMenuItemHandler> menuItems = new LinkedHashMap<>();
    private final String[] commandLineArguments;

    private final PrintStream stdout;
    private final PrintStream stderr;
    private final Runnable scopeChangeRelay = this::fireScopeChange;
    private String extensionFilename = "";
    private boolean extensionBapp;
    private Runnable unloadAction = () -> { };

    public BurpExtenderCallbacksImpl(ProxyServer proxy, String[] commandLineArguments,
                                     PrintStream stdout, PrintStream stderr) {
        this.proxy = proxy;
        this.commandLineArguments = commandLineArguments.clone();
        this.stdout = stdout;
        this.stderr = stderr;
        proxy.scope().addChangeListener(scopeChangeRelay);
    }

    /** Detaches host-level listeners owned by this callbacks instance. */
    public void dispose() {
        proxy.scope().removeChangeListener(scopeChangeRelay);
    }

    public List<IProxyListener> proxyListeners() {
        return proxyListeners;
    }

    public List<IHttpListener> httpListeners() {
        return httpListeners;
    }

    public List<IScopeChangeListener> scopeListeners() {
        return scopeListeners;
    }

    public List<IExtensionStateListener> stateListeners() {
        return stateListeners;
    }

    public List<ITab> suiteTabs() {
        return suiteTabs;
    }

    /** Internal accessor used by extension hosts to observe scope changes. */
    public Scope scope() {
        return proxy.scope();
    }

    public String extensionName() {
        return extensionName.get();
    }

    public void setExtensionFilename(String filename) {
        this.extensionFilename = filename == null ? "" : filename;
    }

    public void setUnloadAction(Runnable action) {
        this.unloadAction = action;
    }

    @Override
    public void setExtensionName(String name) {
        extensionName.set(name == null ? "Unnamed extension" : name);
    }

    @Override
    public String getExtensionFilename() {
        return extensionFilename;
    }

    @Override
    public boolean isExtensionBapp() {
        return extensionBapp;
    }

    @Override
    public String[] getBurpVersion() {
        return new String[]{"Blurp Suite", "1.0.0", "community"};
    }

    @Override
    public String[] getCommandLineArguments() {
        return commandLineArguments.clone();
    }

    @Override
    public String getToolName(int toolFlag) {
        return switch (toolFlag) {
            case TOOL_SUITE -> "Suite";
            case TOOL_TARGET -> "Target";
            case TOOL_PROXY -> "Proxy";
            case TOOL_SPIDER -> "Spider";
            case TOOL_SCANNER -> "Scanner";
            case TOOL_INTRUDER -> "Intruder";
            case TOOL_REPEATER -> "Repeater";
            case TOOL_SEQUENCER -> "Sequencer";
            case TOOL_DECODER -> "Decoder";
            case TOOL_COMPARER -> "Comparer";
            case TOOL_EXTENDER -> "Extender";
            default -> "Unknown";
        };
    }

    @Override
    public IExtensionHelpers getHelpers() {
        return helpers;
    }

    @Override
    public void printOutput(String output) {
        stdout.println("[" + extensionName.get() + "] " + output);
        stdout.flush();
    }

    @Override
    public void printError(String error) {
        stderr.println("[" + extensionName.get() + "] " + error);
        stderr.flush();
    }

    @Override
    public void issueAlert(String message) {
        printOutput("ALERT: " + message);
    }

    @Override
    public OutputStream getStdout() {
        return stdout;
    }

    @Override
    public OutputStream getStderr() {
        return stderr;
    }

    @Override
    public void registerProxyListener(IProxyListener listener) {
        proxyListeners.add(listener);
    }

    @Override
    public void removeProxyListener(IProxyListener listener) {
        proxyListeners.remove(listener);
    }

    @Override
    public List<IProxyListener> getProxyListeners() {
        return Collections.unmodifiableList(new ArrayList<>(proxyListeners));
    }

    @Override
    public void registerHttpListener(IHttpListener listener) {
        httpListeners.add(listener);
    }

    @Override
    public void removeHttpListener(IHttpListener listener) {
        httpListeners.remove(listener);
    }

    @Override
    public List<IHttpListener> getHttpListeners() {
        return Collections.unmodifiableList(new ArrayList<>(httpListeners));
    }

    @Override
    public void registerScopeChangeListener(IScopeChangeListener listener) {
        scopeListeners.add(listener);
    }

    @Override
    public void removeScopeChangeListener(IScopeChangeListener listener) {
        scopeListeners.remove(listener);
    }

    @Override
    public List<IScopeChangeListener> getScopeChangeListeners() {
        return Collections.unmodifiableList(new ArrayList<>(scopeListeners));
    }

    @Override
    public void registerExtensionStateListener(IExtensionStateListener listener) {
        stateListeners.add(listener);
    }

    @Override
    public void removeExtensionStateListener(IExtensionStateListener listener) {
        stateListeners.remove(listener);
    }

    @Override
    public List<IExtensionStateListener> getExtensionStateListeners() {
        return Collections.unmodifiableList(new ArrayList<>(stateListeners));
    }

    /** Internal helper: notifies registered state listeners that an extension is unloading. */
    public void notifyExtensionStateListeners() {
        for (IExtensionStateListener listener : stateListeners) {
            try {
                listener.extensionUnloaded();
            } catch (RuntimeException e) {
                printError("state listener failed: " + e);
            }
        }
    }

    @Override
    public void registerContextMenuFactory(IContextMenuFactory factory) {
        contextMenuFactories.add(factory);
    }

    @Override
    public void removeContextMenuFactory(IContextMenuFactory factory) {
        contextMenuFactories.remove(factory);
    }

    @Override
    public List<IContextMenuFactory> getContextMenuFactories() {
        return Collections.unmodifiableList(new ArrayList<>(contextMenuFactories));
    }

    @Override
    public void registerMessageEditorTabFactory(IMessageEditorTabFactory factory) {
        messageEditorTabFactories.add(factory);
    }

    @Override
    public void removeMessageEditorTabFactory(IMessageEditorTabFactory factory) {
        messageEditorTabFactories.remove(factory);
    }

    @Override
    public List<IMessageEditorTabFactory> getMessageEditorTabFactories() {
        return Collections.unmodifiableList(new ArrayList<>(messageEditorTabFactories));
    }

    @Override
    public void registerIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory factory) {
        payloadGeneratorFactories.add(factory);
    }

    @Override
    public void removeIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory factory) {
        payloadGeneratorFactories.remove(factory);
    }

    @Override
    public List<IIntruderPayloadGeneratorFactory> getIntruderPayloadGeneratorFactories() {
        return Collections.unmodifiableList(new ArrayList<>(payloadGeneratorFactories));
    }

    @Override
    public void registerIntruderPayloadProcessor(IIntruderPayloadProcessor processor) {
        payloadProcessors.add(processor);
    }

    @Override
    public void removeIntruderPayloadProcessor(IIntruderPayloadProcessor processor) {
        payloadProcessors.remove(processor);
    }

    @Override
    public List<IIntruderPayloadProcessor> getIntruderPayloadProcessors() {
        return Collections.unmodifiableList(new ArrayList<>(payloadProcessors));
    }

    @Override
    public void registerScannerCheck(IScannerCheck check) {
        scannerChecks.add(check);
    }

    @Override
    public void removeScannerCheck(IScannerCheck check) {
        scannerChecks.remove(check);
    }

    @Override
    public List<IScannerCheck> getScannerChecks() {
        return Collections.unmodifiableList(new ArrayList<>(scannerChecks));
    }

    @Override
    public void registerScannerInsertionPointProvider(IScannerInsertionPointProvider provider) {
        insertionPointProviders.add(provider);
    }

    @Override
    public void removeScannerInsertionPointProvider(IScannerInsertionPointProvider provider) {
        insertionPointProviders.remove(provider);
    }

    @Override
    public List<IScannerInsertionPointProvider> getScannerInsertionPointProviders() {
        return Collections.unmodifiableList(new ArrayList<>(insertionPointProviders));
    }

    @Override
    public void registerScannerListener(IScannerListener listener) {
        scannerListeners.add(listener);
    }

    @Override
    public void removeScannerListener(IScannerListener listener) {
        scannerListeners.remove(listener);
    }

    @Override
    public List<IScannerListener> getScannerListeners() {
        return Collections.unmodifiableList(new ArrayList<>(scannerListeners));
    }

    @Override
    public void registerSessionHandlingAction(ISessionHandlingAction action) {
        sessionHandlingActions.add(action);
    }

    @Override
    public void removeSessionHandlingAction(ISessionHandlingAction action) {
        sessionHandlingActions.remove(action);
    }

    @Override
    public List<ISessionHandlingAction> getSessionHandlingActions() {
        return Collections.unmodifiableList(new ArrayList<>(sessionHandlingActions));
    }

    @Override
    public void registerMenuItem(String menuItemCaption, IMenuItemHandler menuItemHandler) {
        menuItems.put(menuItemCaption, menuItemHandler);
    }

    @Override
    public void addSuiteTab(ITab tab) {
        suiteTabs.add(tab);
    }

    @Override
    public void removeSuiteTab(ITab tab) {
        suiteTabs.remove(tab);
    }

    @Override
    public void customizeUiComponent(java.awt.Component component) {
        component.setFont(component.getFont().deriveFont(12f));
    }

    @Override
    public ITextEditor createTextEditor() {
        return new TextEditorImpl();
    }

    @Override
    public IMessageEditor createMessageEditor(IMessageEditorController controller, boolean editable) {
        return new MessageEditorImpl(editable);
    }

    @Override
    public void addToSiteMap(IHttpRequestResponse item) {
        siteMap.add(item);
    }

    @Override
    public IHttpRequestResponse[] getSiteMap(String urlPrefix) {
        return matching(siteMap, urlPrefix);
    }

    @Override
    public void addScanIssue(IScanIssue issue) {
        scanIssues.add(issue);
    }

    @Override
    public IScanIssue[] getScanIssues(String urlPrefix) {
        List<IScanIssue> result = new ArrayList<>();
        for (IScanIssue issue : scanIssues) {
            if (urlPrefix == null || urlPrefix.isEmpty()
                    || (issue.getUrl() != null && issue.getUrl().toExternalForm().startsWith(urlPrefix))) {
                result.add(issue);
            }
        }
        return result.toArray(new IScanIssue[0]);
    }

    @Override
    public IHttpRequestResponse[] getProxyHistory() {
        return proxy.history().toArray(new IHttpRequestResponse[0]);
    }

    @Override
    public IHttpRequestResponseWithMarkers applyMarkers(IHttpRequestResponse base,
                                                        List<int[]> requestMarkers,
                                                        List<int[]> responseMarkers) {
        HttpExchange marked = new HttpExchange(System.nanoTime(), base.getRequest(), base.getHttpService(),
                "marker", "");
        marked.setResponse(base.getResponse());
        marked.setMarkers(requestMarkers, responseMarkers);
        return marked;
    }

    @Override
    public String[] getHeaders(byte[] message) {
        return HttpParser.headerLines(message).toArray(new String[0]);
    }

    @Override
    public String[][] getParameters(byte[] request) {
        return HttpParser.parameterRows(request);
    }

    @Override
    public boolean isInScope(URL url) {
        return proxy.scope().isInScope(url);
    }

    @Override
    public void includeInScope(URL url) {
        proxy.scope().include(url.toExternalForm());
    }

    @Override
    public void excludeFromScope(URL url) {
        proxy.scope().exclude(url.toExternalForm());
    }

    private void fireScopeChange() {
        for (IScopeChangeListener listener : scopeListeners) {
            try {
                listener.scopeChanged();
            } catch (RuntimeException e) {
                printError("scope listener failed: " + e);
            }
        }
    }

    @Override
    public void setProxyInterceptionEnabled(boolean enabled) {
        proxy.setInterceptionEnabled(enabled);
    }

    @Override
    public IHttpRequestResponse makeHttpRequest(IHttpService service, byte[] request) {
        return makeHttpRequest(service, request, true);
    }

    @Override
    public IHttpRequestResponse makeHttpRequest(IHttpService service, byte[] request, boolean forceHttp1) {
        byte[] response = rawRequest(service, request);
        HttpExchange result = new HttpExchange(System.nanoTime(), request, service, "extension", "");
        if (response != null) {
            result.setResponse(response);
        }
        addToSiteMap(result);
        return result;
    }

    @Override
    public byte[] makeHttpRequest(String host, int port, boolean useHttps, byte[] request) {
        return rawRequest(new Service(host, port, useHttps ? "https" : "http"), request);
    }

    @Override
    public byte[] makeHttpRequest(String host, int port, boolean useHttps, byte[] request, boolean forceHttp1) {
        return makeHttpRequest(host, port, useHttps, request);
    }

    @Override
    public byte[] makeHttp2Request(IHttpService service, List<IHttpHeader> headers, byte[] body) {
        return makeHttp2Request(service, headers, body, false, "");
    }

    @Override
    public byte[] makeHttp2Request(IHttpService service, List<IHttpHeader> headers, byte[] body,
                                   boolean forceHttp2) {
        return makeHttp2Request(service, headers, body, forceHttp2, "");
    }

    @Override
    public byte[] makeHttp2Request(IHttpService service, List<IHttpHeader> headers, byte[] body,
                                   boolean forceHttp2, String connectionIdentifier) {
        List<String> lines = new ArrayList<>();
        lines.add("POST / HTTP/1.1");
        for (IHttpHeader header : headers) {
            lines.add(header.getName() + ": " + header.getValue());
        }
        if (forceHttp2) {
            printError("HTTP/2 is not available; sending the equivalent HTTP/1.1 request");
        }
        return rawRequest(service, helpers.buildHttpMessage(lines, body));
    }

    private static byte[] rawRequest(IHttpService service, byte[] request) {
        if (service == null || "https".equalsIgnoreCase(service.getProtocol())) {
            // Plain sockets cannot speak TLS; a dedicated TLS transport is on the roadmap.
            return null;
        }
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(service.getHost(), service.getPort()), 10_000);
            socket.setSoTimeout(10_000);
            socket.getOutputStream().write(ProxyServer.originForm(request));
            socket.getOutputStream().flush();
            return ProxyServer.readMessage(socket.getInputStream());
        } catch (IOException e) {
            System.err.println("[callbacks] request failed: " + e.getMessage());
            return null;
        }
    }

    @Override
    public IScanQueueItem doActiveScan(String host, int port, boolean useHttps, byte[] request) {
        return new UnavailableScanQueueItem();
    }

    @Override
    public IScanQueueItem doActiveScan(String host, int port, boolean useHttps, byte[] request,
                                       List<int[]> insertionPointOffsets) {
        return new UnavailableScanQueueItem();
    }

    @Override
    public void doPassiveScan(String host, int port, boolean useHttps, byte[] request, byte[] response) {
        HttpExchange exchange = new HttpExchange(System.nanoTime(), request,
                new Service(host, port, useHttps ? "https" : "http"), "passive", "");
        exchange.setResponse(response);
        addToSiteMap(exchange);
    }

    @Override
    public void generateScanReport(String format, IScanIssue[] issues, File file) {
        StringBuilder report = new StringBuilder("<html><body><h1>Blurp Suite scan report</h1><ul>");
        for (IScanIssue issue : issues) {
            report.append("<li><b>").append(escape(issue.getIssueName())).append("</b> - ")
                    .append(escape(issue.getSeverity())).append("</li>");
        }
        report.append("</ul></body></html>");
        try {
            Files.writeString(file.toPath(), report);
        } catch (IOException e) {
            printError("could not write scan report: " + e.getMessage());
        }
    }

    @Override
    public void updateCookieJar(ICookie cookie) {
        cookieJar.add(cookie);
    }

    @Override
    public List<ICookie> getCookieJarContents() {
        return Collections.unmodifiableList(new ArrayList<>(cookieJar));
    }

    @Override
    public void sendToComparer(byte[] data) {
        printOutput("sendToComparer: " + data.length + " bytes buffered");
    }

    @Override
    public void sendToIntruder(String host, int port, boolean useHttps, byte[] request) {
        sendToIntruder(host, port, useHttps, request, Collections.emptyList());
    }

    @Override
    public void sendToIntruder(String host, int port, boolean useHttps, byte[] request,
                               List<int[]> payloadPositionOffsets) {
        addToSiteMap(new HttpExchange(System.nanoTime(), request,
                new Service(host, port, useHttps ? "https" : "http"), "intruder", ""));
        printOutput("sendToIntruder: request queued");
    }

    @Override
    public void sendToRepeater(String host, int port, boolean useHttps, byte[] request, String tabCaption) {
        addToSiteMap(new HttpExchange(System.nanoTime(), request,
                new Service(host, port, useHttps ? "https" : "http"), "repeater", ""));
        printOutput("sendToRepeater: " + tabCaption + " queued");
    }

    @Override
    public void sendToSpider(URL url) {
        printOutput("sendToSpider: " + url);
    }

    @Override
    public void saveExtensionSetting(String name, String value) {
        synchronized (settings) {
            settings.put(name, value);
        }
    }

    @Override
    public String loadExtensionSetting(String name) {
        synchronized (settings) {
            return settings.get(name);
        }
    }

    @Override
    public Map<String, String> saveConfig() {
        synchronized (settings) {
            return new LinkedHashMap<>(settings);
        }
    }

    @Override
    public void loadConfig(Map<String, String> config) {
        synchronized (settings) {
            settings.putAll(config);
        }
    }

    @Override
    public String saveConfigAsJson(String... configPaths) {
        synchronized (settings) {
            return Json.write(new LinkedHashMap<>(settings));
        }
    }

    @Override
    public void loadConfigFromJson(String config) {
        Object parsed = Json.parse(config);
        if (parsed instanceof Map<?, ?> map) {
            synchronized (settings) {
                map.forEach((key, value) -> settings.put(String.valueOf(key), String.valueOf(value)));
            }
        }
    }

    @Override
    public ITempFile saveToTempFile(byte[] buffer) {
        try {
            return new TempFileImpl(buffer);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to persist buffer", e);
        }
    }

    @Override
    public IHttpRequestResponsePersisted saveBuffersToTempFiles(IHttpRequestResponse httpRequestResponse) {
        // HttpExchange keeps buffers in memory and implements the persisted contract.
        return httpRequestResponse instanceof IHttpRequestResponsePersisted persisted
                ? persisted : new HttpExchange(System.nanoTime(), httpRequestResponse.getRequest(),
                httpRequestResponse.getHttpService(), "persisted", "");
    }

    @Override
    public void saveState(File file) {
        Properties properties = new Properties();
        synchronized (settings) {
            properties.putAll(settings);
        }
        try (var writer = Files.newBufferedWriter(file.toPath())) {
            properties.store(writer, "Blurp Suite extension state");
        } catch (IOException e) {
            printError("could not save state: " + e.getMessage());
        }
    }

    @Override
    public void restoreState(File file) {
        Properties properties = new Properties();
        try (var reader = Files.newBufferedReader(file.toPath())) {
            properties.load(reader);
            synchronized (settings) {
                properties.forEach((key, value) -> settings.put(String.valueOf(key), String.valueOf(value)));
            }
        } catch (IOException e) {
            printError("could not restore state: " + e.getMessage());
        }
    }

    @Override
    public void exitSuite(boolean promptUser) {
        if (!promptUser) {
            System.exit(0);
        } else {
            printOutput("exitSuite(promptUser=true) ignored in headless callback context");
        }
    }

    @Override
    public void unloadExtension() {
        unloadAction.run();
    }

    @Override
    public IBurpCollaboratorClientContext createBurpCollaboratorClientContext() {
        return CollaboratorSupport.context();
    }

    private static IHttpRequestResponse[] matching(List<IHttpRequestResponse> source, String prefix) {
        List<IHttpRequestResponse> result = new ArrayList<>();
        for (IHttpRequestResponse item : source) {
            if (prefix == null || prefix.isEmpty()) {
                result.add(item);
                continue;
            }
            String url = HttpParser.requestUrl(item.getRequest(), item.getHttpService()).toExternalForm();
            if (url.startsWith(prefix)) {
                result.add(item);
            }
        }
        return result.toArray(new IHttpRequestResponse[0]);
    }

    private static String escape(String value) {
        return value == null ? "" : value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /** Placeholder queue item for the scanner, which is intentionally not implemented yet. */
    private static final class UnavailableScanQueueItem implements IScanQueueItem {
        @Override
        public void cancel() {
            // No active scan was started.
        }

        @Override
        public IScanIssue[] getIssues() {
            return new IScanIssue[0];
        }

        @Override
        public int getNumErrors() {
            return 0;
        }

        @Override
        public int getNumInsertionPoints() {
            return 0;
        }

        @Override
        public int getNumRequests() {
            return 0;
        }

        @Override
        public byte getPercentageComplete() {
            return 100;
        }

        @Override
        public String getStatus() {
            return "Active scanning is not implemented in Blurp Suite";
        }
    }
}
