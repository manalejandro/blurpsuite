package com.blurpsuite.extensions;

import com.blurpsuite.util.Json;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;

/**
 * Tiny line-delimited JSON-RPC connection used to talk to Python extensions.
 *
 * <p>A single reader thread demultiplexes replies and peer-initiated calls, so an
 * extension can call back into the host while it is handling a proxy event
 * without deadlocking.</p>
 */
public final class JrpcConnection implements AutoCloseable {
    private final Process process;
    private final BufferedWriter writer;
    private final Map<Integer, CompletableFuture<Map<String, Object>>> pending = new ConcurrentHashMap<>();
    private final AtomicInteger nextId = new AtomicInteger(1);
    private final BiFunction<String, Map<String, Object>, Object> handler;
    private final Thread readerThread;
    private volatile boolean running = true;
    private volatile long timeoutSeconds = 10;

    public JrpcConnection(Process process,
                          BiFunction<String, Map<String, Object>, Object> handler) {
        this.process = process;
        this.writer = new BufferedWriter(new OutputStreamWriter(
                process.getOutputStream(), StandardCharsets.UTF_8));
        this.handler = handler;
        this.readerThread = new Thread(this::readLoop, "blurp-jrpc-reader");
        this.readerThread.setDaemon(true);
        this.readerThread.start();
    }

    /** Sends a request and waits for the peer's reply. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> request(String method, Map<String, Object> params) {
        int id = nextId.getAndIncrement();
        CompletableFuture<Map<String, Object>> future = new CompletableFuture<>();
        pending.put(id, future);
        try {
            send(id, method, params);
            return future.get(timeoutSeconds, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            throw new IllegalStateException("Python extension timed out on '" + method + "'", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while calling '" + method + "'", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException runtime) {
                throw runtime;
            }
            throw new IllegalStateException("Python extension failed on '" + method + "'", cause);
        } finally {
            pending.remove(id);
        }
    }

    /** Sends a one-way notification. */
    public void notify(String method, Map<String, Object> params) {
        send(null, method, params);
    }

    private synchronized void send(Integer id, String method, Map<String, Object> params) {
        Map<String, Object> message = Json.obj();
        if (id != null) {
            message.put("id", id);
        }
        message.put("method", method);
        message.put("params", params == null ? Json.obj() : params);
        try {
            writer.write(Json.write(message));
            writer.newLine();
            writer.flush();
        } catch (IOException e) {
            throw new IllegalStateException("Unable to write to Python extension", e);
        }
    }

    private synchronized void sendResult(int id, Object result, String error) {
        Map<String, Object> message = Json.obj();
        message.put("id", id);
        if (error != null) {
            message.put("error", error);
        } else {
            message.put("result", result == null ? "" : result);
        }
        try {
            writer.write(Json.write(message));
            writer.newLine();
            writer.flush();
        } catch (IOException e) {
            running = false;
        }
    }

    private void invokeHandler(String method, Object params) {
        Map<String, Object> arguments = params instanceof Map<?, ?> map
                ? cast(map) : Json.obj();
        try {
            handler.apply(method, arguments);
        } catch (RuntimeException e) {
            System.err.println("[python] notification '" + method + "' failed: " + e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> cast(Map<?, ?> map) {
        return (Map<String, Object>) map;
    }

    @SuppressWarnings("unchecked")
    private void readLoop() {
        BufferedReader reader = new BufferedReader(new InputStreamReader(
                process.getInputStream(), StandardCharsets.UTF_8));
        while (running) {
            try {
                String line = reader.readLine();
                if (line == null) {
                    break;
                }
                Object parsed = Json.parse(line);
                if (!(parsed instanceof Map<?, ?> raw)) {
                    continue;
                }
                Map<String, Object> message = (Map<String, Object>) raw;
                Object idValue = message.get("id");
                String method = Json.string(message.get("method"), "");
                if (!(idValue instanceof Number number)) {
                    // JSON-RPC notifications have no id. They are one-way calls from
                    // the Python extension (printOutput, unloadExtension, ...), so
                    // the handler runs but no reply is written back.
                    if (!method.isEmpty() && !message.containsKey("result")
                            && !message.containsKey("error")) {
                        invokeHandler(method, message.get("params"));
                    }
                    continue;
                }
                int id = number.intValue();
                if (message.containsKey("result") || message.containsKey("error")) {
                    CompletableFuture<Map<String, Object>> future = pending.remove(id);
                    if (future == null) {
                        continue;
                    }
                    if (message.containsKey("error")) {
                        future.completeExceptionally(new RuntimeException(
                                String.valueOf(message.get("error"))));
                    } else {
                        Object result = message.get("result");
                        future.complete(result instanceof Map<?, ?> map
                                ? (Map<String, Object>) map : Json.obj());
                    }
                } else if (!method.isEmpty()) {
                    Object params = message.get("params");
                    Map<String, Object> arguments = params instanceof Map<?, ?> map
                            ? (Map<String, Object>) map : Json.obj();
                    try {
                        Object result = handler.apply(method, arguments);
                        sendResult(id, result, null);
                    } catch (RuntimeException e) {
                        sendResult(id, null, e.toString());
                    }
                }
            } catch (IOException e) {
                if (running) {
                    System.err.println("[python] RPC read failed: " + e.getMessage());
                }
                break;
            } catch (RuntimeException e) {
                System.err.println("[python] malformed RPC message: " + e.getMessage());
            }
        }
        running = false;
        for (CompletableFuture<Map<String, Object>> future : pending.values()) {
            future.completeExceptionally(new IllegalStateException("Python extension exited"));
        }
        pending.clear();
    }

    @Override
    public void close() {
        running = false;
        readerThread.interrupt();
        try {
            writer.close();
        } catch (IOException ignored) {
            // Best effort.
        }
    }
}
