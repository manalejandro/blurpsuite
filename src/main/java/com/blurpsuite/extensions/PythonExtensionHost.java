package com.blurpsuite.extensions;

import burp.IBurpExtenderCallbacks;
import burp.ICookie;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IInterceptedProxyMessage;
import burp.IScanIssue;
import com.blurpsuite.api.BurpExtenderCallbacksImpl;
import com.blurpsuite.core.HttpExchange;
import com.blurpsuite.core.Service;
import com.blurpsuite.core.TrafficListener;
import com.blurpsuite.util.Json;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Runs a Python extension in a child process and bridges proxy traffic to it. */
public final class PythonExtensionHost implements TrafficListener, AutoCloseable {
    private static final int MAX_REHOOK_PASSES = 8;

    private final BurpExtenderCallbacksImpl callbacks;
    private final Process process;
    private final JrpcConnection rpc;
    private final AtomicReference<HttpExchange> currentExchange = new AtomicReference<>();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final Path script;
    private volatile String extensionName = "Python extension";
    private volatile boolean hasHttpListeners;
    private volatile Runnable scopeNotification;

    public PythonExtensionHost(BurpExtenderCallbacksImpl callbacks, Path script, Path pythonHome,
                               String pythonExecutable) throws IOException {
        this.callbacks = callbacks;
        this.script = script.toAbsolutePath().normalize();

        ProcessBuilder builder = new ProcessBuilder(pythonExecutable, "-m", "blurp.bridge",
                this.script.toString());
        builder.environment().put("PYTHONPATH", pythonHome.toAbsolutePath().normalize().toString());
        builder.redirectErrorStream(false);
        // Python diagnostics go straight to the host's stderr; stdout stays a clean RPC pipe.
        builder.redirectError(ProcessBuilder.Redirect.INHERIT);
        this.process = builder.start();
        this.rpc = new JrpcConnection(process, this::handlePeerCall);
    }

    /** Reads the extension name reported by the Python side after loading. */
    public String initialize() {
        Map<String, Object> reply = rpc.request("get_extension_info", Json.obj());
        extensionName = Json.string(reply.get("name"), script.getFileName().toString());
        callbacks.setExtensionName(extensionName);
        hasHttpListeners = Json.integer(reply.get("httpListeners"), 0) > 0;
        updateScopeListenerRegistration(Json.integer(reply.get("scopeListeners"), 0) > 0);
        return extensionName;
    }

    public String name() {
        return extensionName;
    }

    @Override
    public boolean onMessage(boolean messageIsRequest, HttpExchange exchange) {
        currentExchange.set(exchange);
        try {
            Map<String, Object> reply = Json.obj();
            int action = IInterceptedProxyMessage.ACTION_FOLLOW_RULES;
            // Rehook actions ask Burp to pass the modified message through the
            // proxy listeners again. Bound the loop so a buggy extension cannot
            // deadlock the proxy by rehooking forever.
            for (int pass = 0; pass <= MAX_REHOOK_PASSES; pass++) {
                reply = rpc.request("on_proxy_message", proxyParams(messageIsRequest, exchange));
                applyReply(messageIsRequest, exchange, reply);
                action = Json.integer(reply.get("action"), IInterceptedProxyMessage.ACTION_FOLLOW_RULES);
                if (!isRehookAction(action) || pass == MAX_REHOOK_PASSES) {
                    break;
                }
            }

            if (hasHttpListeners) {
                Map<String, Object> httpParams = Json.obj();
                httpParams.put("tool", IBurpExtenderCallbacks.TOOL_PROXY);
                httpParams.put("isRequest", messageIsRequest);
                httpParams.put("message", encode(messageIsRequest
                        ? exchange.getRequest() : exchange.getResponse()));
                httpParams.put("reference", exchange.reference());
                if (exchange.getHttpService() != null) {
                    httpParams.put("service", serviceMap(exchange.getHttpService()));
                }
                applyReply(messageIsRequest, exchange, rpc.request("on_http_message", httpParams));
            }
            boolean drop = Boolean.TRUE.equals(reply.get("drop"))
                    || action == IInterceptedProxyMessage.ACTION_DROP;
            return !drop;
        } finally {
            currentExchange.set(null);
        }
    }

    private static Map<String, Object> proxyParams(boolean messageIsRequest, HttpExchange exchange) {
        Map<String, Object> params = Json.obj();
        params.put("isRequest", messageIsRequest);
        params.put("message", encode(messageIsRequest
                ? exchange.getRequest() : exchange.getResponse()));
        params.put("reference", exchange.reference());
        params.put("listener", exchange.listener());
        params.put("clientAddress", exchange.clientAddress());
        params.put("comment", exchange.getComment() == null ? "" : exchange.getComment());
        params.put("highlight", exchange.getHighlight() == null ? "" : exchange.getHighlight());
        if (exchange.getHttpService() != null) {
            params.put("service", serviceMap(exchange.getHttpService()));
        }
        return params;
    }

    private static boolean isRehookAction(int action) {
        return action == IInterceptedProxyMessage.ACTION_FOLLOW_RULES_AND_REHOOK
                || action == IInterceptedProxyMessage.ACTION_DO_INTERCEPT_AND_REHOOK
                || action == IInterceptedProxyMessage.ACTION_DONT_INTERCEPT_AND_REHOOK;
    }

    private static void applyReply(boolean messageIsRequest, HttpExchange exchange,
                                   Map<String, Object> reply) {
        String message = Json.string(reply.get("message"), null);
        if (message != null) {
            byte[] updated = decode(message);
            if (messageIsRequest) {
                exchange.setRequest(updated);
            } else {
                exchange.setResponse(updated);
            }
        }
        Object comment = reply.get("comment");
        if (comment instanceof String value) {
            exchange.setComment(value);
        }
        Object highlight = reply.get("highlight");
        if (highlight instanceof String value) {
            exchange.setHighlight(value);
        }
    }

    /** Handles calls initiated by the Python extension. */
    private Object handlePeerCall(String method, Map<String, Object> params) {
        return switch (method) {
            case "print_output" -> {
                callbacks.printOutput(Json.string(params.get("message"), ""));
                yield true;
            }
            case "print_error" -> {
                callbacks.printError(Json.string(params.get("message"), ""));
                yield true;
            }
            case "set_http_listener_count" -> {
                hasHttpListeners = Json.integer(params.get("count"), 0) > 0;
                yield true;
            }
            case "set_scope_listener_count" -> {
                updateScopeListenerRegistration(Json.integer(params.get("count"), 0) > 0);
                yield true;
            }
            case "set_request" -> {
                HttpExchange exchange = currentExchange.get();
                if (exchange != null) {
                    exchange.setRequest(decode(Json.string(params.get("data"), "")));
                }
                yield true;
            }
            case "set_response" -> {
                HttpExchange exchange = currentExchange.get();
                if (exchange != null) {
                    exchange.setResponse(decode(Json.string(params.get("data"), "")));
                }
                yield true;
            }
            case "set_comment" -> {
                HttpExchange exchange = currentExchange.get();
                if (exchange != null) {
                    exchange.setComment(Json.string(params.get("value"), ""));
                }
                yield true;
            }
            case "set_highlight" -> {
                HttpExchange exchange = currentExchange.get();
                if (exchange != null) {
                    exchange.setHighlight(Json.string(params.get("value"), ""));
                }
                yield true;
            }
            case "is_in_scope" -> {
                Map<String, Object> result = Json.obj();
                try {
                    result.put("value", callbacks.isInScope(new URL(Json.string(params.get("url"), ""))));
                } catch (IOException | RuntimeException e) {
                    result.put("value", false);
                }
                yield result;
            }
            case "add_to_site_map" -> {
                byte[] request = decode(Json.string(params.get("request"), ""));
                byte[] response = decode(Json.string(params.get("response"), ""));
                Map<String, Object> rawService = params.get("service") instanceof Map<?, ?> map
                        ? cast(map) : Json.obj();
                Service service = new Service(Json.string(rawService.get("host"), "localhost"),
                        Json.integer(rawService.get("port"), 80),
                        Json.string(rawService.get("protocol"), "http"));
                HttpExchange item = new HttpExchange(System.nanoTime(), request, service, "python", "");
                item.setResponse(response);
                callbacks.addToSiteMap(item);
                yield true;
            }
            case "include_in_scope" -> {
                try {
                    callbacks.includeInScope(new URL(Json.string(params.get("url"), "")));
                } catch (IOException | RuntimeException e) {
                    callbacks.printError("include_in_scope: " + e.getMessage());
                }
                yield true;
            }
            case "exclude_from_scope" -> {
                try {
                    callbacks.excludeFromScope(new URL(Json.string(params.get("url"), "")));
                } catch (IOException | RuntimeException e) {
                    callbacks.printError("exclude_from_scope: " + e.getMessage());
                }
                yield true;
            }
            case "set_interception" -> {
                callbacks.setProxyInterceptionEnabled(Boolean.TRUE.equals(params.get("enabled")));
                yield true;
            }
            case "get_proxy_history" -> {
                List<Object> items = new ArrayList<>();
                for (IHttpRequestResponse item : callbacks.getProxyHistory()) {
                    Map<String, Object> row = Json.obj();
                    row.put("request", encode(item.getRequest()));
                    row.put("response", encode(item.getResponse()));
                    row.put("comment", item.getComment() == null ? "" : item.getComment());
                    row.put("highlight", item.getHighlight() == null ? "" : item.getHighlight());
                    if (item.getHttpService() != null) {
                        row.put("service", serviceMap(item.getHttpService()));
                    }
                    items.add(row);
                }
                Map<String, Object> result = Json.obj();
                result.put("items", items);
                yield result;
            }
            case "make_http_request" -> {
                Map<String, Object> rawService = params.get("service") instanceof Map<?, ?> map
                        ? cast(map) : Json.obj();
                Service service = new Service(Json.string(rawService.get("host"), "localhost"),
                        Json.integer(rawService.get("port"), 80),
                        Json.string(rawService.get("protocol"), "http"));
                IHttpRequestResponse result = callbacks.makeHttpRequest(service,
                        decode(Json.string(params.get("request"), "")));
                Map<String, Object> reply = Json.obj();
                reply.put("request", encode(result == null ? new byte[0] : result.getRequest()));
                reply.put("response", encode(result == null ? new byte[0] : result.getResponse()));
                reply.put("service", serviceMap(service));
                yield reply;
            }
            case "do_passive_scan" -> {
                callbacks.doPassiveScan(Json.string(params.get("host"), ""),
                        Json.integer(params.get("port"), 0),
                        Boolean.TRUE.equals(params.get("useHttps")),
                        decode(Json.string(params.get("request"), "")),
                        decode(Json.string(params.get("response"), "")));
                yield true;
            }
            case "exit_suite" -> {
                callbacks.printOutput("exitSuite requested by Python extension (ignored)");
                yield true;
            }
            case "unload_extension" -> {
                // ExtensionManager installs an action that schedules the real
                // unload on a worker thread, so calling this from the JSON-RPC
                // reader thread cannot block or close its own connection.
                callbacks.unloadExtension();
                yield true;
            }
            default -> throw new IllegalArgumentException("Unknown Python RPC method: " + method);
        };
    }

    private void updateScopeListenerRegistration(boolean needed) {
        if (needed && scopeNotification == null) {
            Runnable notification = () -> rpc.notify("on_scope_changed", Json.obj());
            scopeNotification = notification;
            callbacks.scope().addChangeListener(notification);
        } else if (!needed && scopeNotification != null) {
            callbacks.scope().removeChangeListener(scopeNotification);
            scopeNotification = null;
        }
    }

    private static Map<String, Object> serviceMap(IHttpService service) {
        Map<String, Object> result = Json.obj();
        result.put("host", service.getHost());
        result.put("port", service.getPort());
        result.put("protocol", service.getProtocol());
        return result;
    }

    private static String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data == null ? new byte[0] : data);
    }

    private static byte[] decode(String base64) {
        try {
            return Base64.getDecoder().decode(base64 == null ? "" : base64);
        } catch (IllegalArgumentException e) {
            return new byte[0];
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> cast(Map<?, ?> map) {
        return (Map<String, Object>) map;
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        if (scopeNotification != null) {
            callbacks.scope().removeChangeListener(scopeNotification);
            scopeNotification = null;
        }
        try {
            // Wait for the child to run IExtensionStateListener callbacks before
            // tearing down the pipe, so notification is deterministic.
            rpc.request("on_unloaded", Json.obj());
        } catch (RuntimeException ignored) {
            // Process may already be gone; the child's finally block is the fallback.
        }
        rpc.close();
        process.destroy();
        try {
            if (!process.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
        }
    }
}
