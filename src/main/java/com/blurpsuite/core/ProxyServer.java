package com.blurpsuite.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * HTTP/1.1 intercepting proxy. CONNECT requests are tunnelled without TLS
 * interception; see docs/ROADMAP.md for the planned MITM layer.
 */
public final class ProxyServer {
    private static final int MAX_MESSAGE_SIZE = 16 * 1024 * 1024;
    private static final int SOCKET_TIMEOUT_MS = 30_000;

    private final int port;
    private volatile String bindAddress;
    private final Scope scope = new Scope();
    private final List<TrafficListener> listeners = new CopyOnWriteArrayList<>();
    private final List<HttpExchange> history = new CopyOnWriteArrayList<>();
    private final LinkedBlockingQueue<Interception> interceptQueue = new LinkedBlockingQueue<>();
    private final AtomicBoolean interceptionEnabled = new AtomicBoolean(false);
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong referenceCounter = new AtomicLong(1);

    private volatile ServerSocket serverSocket;
    private volatile Thread acceptThread;

    public ProxyServer(int port, String bindAddress) {
        this.port = port;
        this.bindAddress = bindAddress;
    }

    /** A message paused in the intercept queue, waiting for a human decision. */
    public static final class Interception {
        private final HttpExchange exchange;
        private final boolean request;
        private final CountDownLatch latch = new CountDownLatch(1);
        private volatile boolean dropped;

        private Interception(HttpExchange exchange, boolean request) {
            this.exchange = exchange;
            this.request = request;
        }

        public HttpExchange exchange() {
            return exchange;
        }

        public boolean isRequest() {
            return request;
        }

        public boolean dropped() {
            return dropped;
        }

        public void resolve(boolean drop) {
            dropped = drop;
            latch.countDown();
        }

        private void await() {
            try {
                latch.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                dropped = true;
            }
        }
    }

    public void addListener(TrafficListener listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void removeListener(TrafficListener listener) {
        listeners.remove(listener);
    }

    public Scope scope() {
        return scope;
    }

    public List<HttpExchange> history() {
        return history;
    }

    public int port() {
        return port;
    }

    public String bindAddress() {
        return bindAddress;
    }

    public synchronized void setBindAddress(String address) {
        if (running.get()) {
            throw new IllegalStateException("Stop the proxy before changing the bind address");
        }
        this.bindAddress = address == null || address.isBlank() ? "127.0.0.1" : address.trim();
    }

    public boolean isRunning() {
        return running.get();
    }

    public boolean isInterceptionEnabled() {
        return interceptionEnabled.get();
    }

    public void setInterceptionEnabled(boolean enabled) {
        interceptionEnabled.set(enabled);
        if (!enabled) {
            Interception pending;
            while ((pending = interceptQueue.poll()) != null) {
                pending.resolve(false);
            }
        }
    }

    public Interception pollInterception(long timeout, TimeUnit unit) throws InterruptedException {
        return interceptQueue.poll(timeout, unit);
    }

    public int queuedInterceptions() {
        return interceptQueue.size();
    }

    public synchronized void start() throws IOException {
        if (running.get()) {
            return;
        }
        serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress(bindAddress, port));
        running.set(true);
        acceptThread = new Thread(this::acceptLoop, "blurp-proxy-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    public synchronized void stop() {
        if (!running.getAndSet(false)) {
            return;
        }
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException ignored) {
            // Shutdown is best effort.
        }
        setInterceptionEnabled(false);
        if (acceptThread != null) {
            acceptThread.interrupt();
        }
    }

    private void acceptLoop() {
        while (running.get() && serverSocket != null && !serverSocket.isClosed()) {
            try {
                Socket client = serverSocket.accept();
                client.setSoTimeout(SOCKET_TIMEOUT_MS);
                Thread worker = new Thread(() -> handleClient(client), "blurp-proxy-client");
                worker.setDaemon(true);
                worker.start();
            } catch (IOException e) {
                if (running.get()) {
                    System.err.println("[proxy] accept failed: " + e.getMessage());
                }
            }
        }
    }

    private void handleClient(Socket client) {
        try (client) {
            InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();
            byte[] requestBytes = readMessage(in);
            if (requestBytes.length == 0) {
                return;
            }
            String[] requestLine = HttpParser.startLine(requestBytes);
            String method = requestLine.length > 0 ? requestLine[0].toUpperCase(Locale.ROOT) : "GET";
            if ("CONNECT".equals(method)) {
                tunnel(client, in, out, requestLine.length > 1 ? requestLine[1] : "");
                return;
            }

            Service service = HttpParser.resolveService(requestBytes, null);
            if (service == null) {
                writeResponse(out, simpleResponse(400, "Bad Request", "Missing Host header"));
                return;
            }
            HttpExchange exchange = new HttpExchange(referenceCounter.getAndIncrement(), requestBytes,
                    service, bindAddress + ":" + port,
                    client.getInetAddress() == null ? "" : client.getInetAddress().getHostAddress());
            history.add(exchange);

            if (!scope.isInScope(HttpParser.requestUrl(exchange.getRequest(), service))) {
                writeResponse(out, simpleResponse(403, "Forbidden", "Target is outside the configured scope"));
                return;
            }

            if (!notifyListeners(true, exchange) || !intercept(exchange, true)) {
                return;
            }

            byte[] outgoing = originForm(exchange.getRequest());
            byte[] response = exchange(outgoing, service);
            if (response == null) {
                writeResponse(out, simpleResponse(502, "Bad Gateway", "Upstream request failed"));
                return;
            }
            exchange.setResponse(response);
            if (!notifyListeners(false, exchange) || !intercept(exchange, false)) {
                return;
            }
            writeResponse(out, exchange.getResponse());
        } catch (SocketTimeoutException e) {
            System.err.println("[proxy] client timeout: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("[proxy] connection error: " + e.getMessage());
        } catch (RuntimeException e) {
            System.err.println("[proxy] handler error: " + e);
        }
    }

    private boolean notifyListeners(boolean isRequest, HttpExchange exchange) {
        for (TrafficListener listener : listeners) {
            try {
                if (!listener.onMessage(isRequest, exchange)) {
                    return false;
                }
            } catch (RuntimeException e) {
                System.err.println("[proxy] listener '" + listener + "' failed: " + e);
            }
        }
        return true;
    }

    private boolean intercept(HttpExchange exchange, boolean isRequest) {
        if (!interceptionEnabled.get()) {
            return true;
        }
        Interception pending = new Interception(exchange, isRequest);
        interceptQueue.add(pending);
        pending.await();
        return !pending.dropped();
    }

    private static byte[] exchange(byte[] request, Service service) {
        try (Socket upstream = new Socket()) {
            upstream.connect(new InetSocketAddress(service.getHost(), service.getPort()), SOCKET_TIMEOUT_MS);
            upstream.setSoTimeout(SOCKET_TIMEOUT_MS);
            OutputStream out = upstream.getOutputStream();
            out.write(request);
            out.flush();
            return readMessage(upstream.getInputStream());
        } catch (IOException e) {
            System.err.println("[proxy] upstream " + service + ": " + e.getMessage());
            return null;
        }
    }

    /** Replaces an absolute request target with its origin form for upstream delivery. */
    public static byte[] originForm(byte[] request) {
        String[] line = HttpParser.startLine(request);
        if (line.length < 2 || !(line[1].startsWith("http://") || line[1].startsWith("https://"))) {
            return request;
        }
        String path;
        try {
            java.net.URL url = new java.net.URL(line[1]);
            path = url.getPath().isEmpty() ? "/" : url.getPath();
            if (url.getQuery() != null) {
                path += "?" + url.getQuery();
            }
        } catch (java.net.MalformedURLException e) {
            return request;
        }
        String text = com.blurpsuite.util.ByteUtil.toString(request);
        int lineEnd = text.indexOf('\n');
        if (lineEnd < 0) {
            return request;
        }
        String firstLine = text.substring(0, lineEnd).replace("\r", "");
        String[] parts = firstLine.split("\\s+", 3);
        String replacement = parts[0] + " " + path + (parts.length > 2 ? " " + parts[2] : " HTTP/1.1");
        return com.blurpsuite.util.ByteUtil.toBytes(replacement + text.substring(lineEnd));
    }

    /** Reads one HTTP message, honouring Content-Length and chunked transfer encoding. */
    public static byte[] readMessage(InputStream in) throws IOException {
        ByteArrayOutputStream headerBuffer = new ByteArrayOutputStream();
        int current;
        int previous = -1;
        int beforePrevious = -1;
        int thirdPrevious = -1;
        while ((current = in.read()) != -1) {
            headerBuffer.write(current);
            boolean lfLf = previous == '\n' && current == '\n';
            boolean crLfCrLf = thirdPrevious == '\r' && beforePrevious == '\n'
                    && previous == '\r' && current == '\n';
            if (lfLf || crLfCrLf) {
                break;
            }
            thirdPrevious = beforePrevious;
            beforePrevious = previous;
            previous = current;
            if (headerBuffer.size() > MAX_MESSAGE_SIZE) {
                throw new IOException("header block too large");
            }
        }
        if (headerBuffer.size() == 0) {
            return new byte[0];
        }
        byte[] headers = headerBuffer.toByteArray();
        String headerText = com.blurpsuite.util.ByteUtil.toString(headers).toLowerCase(Locale.ROOT);
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        message.write(headers);

        if (headerText.contains("transfer-encoding:") && headerText.contains("chunked")) {
            readChunks(in, message);
        } else {
            int contentLength = 0;
            for (String line : headerText.split("\\r?\\n")) {
                if (line.startsWith("content-length:")) {
                    try {
                        contentLength = Integer.parseInt(line.substring(15).trim());
                    } catch (NumberFormatException ignored) {
                        contentLength = 0;
                    }
                    break;
                }
            }
            if (contentLength < 0 || contentLength > MAX_MESSAGE_SIZE) {
                throw new IOException("invalid Content-Length: " + contentLength);
            }
            byte[] buffer = new byte[8192];
            int remaining = contentLength;
            while (remaining > 0) {
                int read = in.read(buffer, 0, Math.min(buffer.length, remaining));
                if (read < 0) {
                    break;
                }
                message.write(buffer, 0, read);
                remaining -= read;
            }
        }
        return message.toByteArray();
    }

    private static void readChunks(InputStream in, ByteArrayOutputStream out) throws IOException {
        while (true) {
            String sizeLine = readLine(in);
            if (sizeLine == null) {
                break;
            }
            int size;
            try {
                size = Integer.parseInt(sizeLine.split(";", 2)[0].trim(), 16);
            } catch (NumberFormatException e) {
                throw new IOException("invalid chunk size: " + sizeLine);
            }
            if (size == 0) {
                String trailer = readLine(in);
                while (trailer != null && !trailer.isEmpty()) {
                    trailer = readLine(in);
                }
                break;
            }
            if (size > MAX_MESSAGE_SIZE) {
                throw new IOException("chunk too large");
            }
            byte[] chunk = new byte[size];
            int read = 0;
            while (read < size) {
                int count = in.read(chunk, read, size - read);
                if (count < 0) {
                    throw new IOException("truncated chunked body");
                }
                read += count;
            }
            out.write(chunk);
            readLine(in);
        }
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int current;
        while ((current = in.read()) != -1) {
            if (current == '\n') {
                return line.toString(java.nio.charset.StandardCharsets.ISO_8859_1).trim();
            }
            line.write(current);
        }
        return null;
    }

    private static void tunnel(Socket client, InputStream in, OutputStream out, String target) {
        try {
            String[] parts = target.split(":", 2);
            int portNumber = parts.length > 1 ? Integer.parseInt(parts[1]) : 443;
            try (Socket upstream = new Socket(parts[0], portNumber)) {
                out.write(com.blurpsuite.util.ByteUtil.toBytes("HTTP/1.1 200 Connection Established\r\n\r\n"));
                out.flush();
                InputStream upstreamIn = upstream.getInputStream();
                OutputStream upstreamOut = upstream.getOutputStream();
                Thread toUpstream = new Thread(() -> copy(in, upstreamOut), "blurp-tunnel-up");
                Thread toClient = new Thread(() -> copy(upstreamIn, out), "blurp-tunnel-down");
                toUpstream.setDaemon(true);
                toClient.setDaemon(true);
                toUpstream.start();
                toClient.start();
                toClient.join();
            }
        } catch (IOException | NumberFormatException e) {
            System.err.println("[proxy] CONNECT to " + target + " failed: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void copy(InputStream in, OutputStream out) {
        byte[] buffer = new byte[8192];
        try {
            int count;
            while ((count = in.read(buffer)) != -1) {
                out.write(buffer, 0, count);
                out.flush();
            }
        } catch (IOException ignored) {
            // Either side closed the tunnel.
        }
    }

    private static byte[] simpleResponse(int status, String reason, String body) {
        byte[] content = com.blurpsuite.util.ByteUtil.toBytes(body);
        String response = "HTTP/1.1 " + status + " " + reason + "\r\n"
                + "Content-Type: text/plain; charset=utf-8\r\n"
                + "Content-Length: " + content.length + "\r\n"
                + "Connection: close\r\n\r\n";
        return com.blurpsuite.util.ByteUtil.concat(
                com.blurpsuite.util.ByteUtil.toBytes(response), content);
    }

    private static void writeResponse(OutputStream out, byte[] response) throws IOException {
        out.write(response);
        out.flush();
    }

    /** Returns a copy of the current history, newest first. */
    public List<HttpExchange> recentHistory(int limit) {
        List<HttpExchange> copy = new ArrayList<>(history);
        List<HttpExchange> result = new ArrayList<>();
        for (int i = copy.size() - 1; i >= 0 && result.size() < limit; i--) {
            result.add(copy.get(i));
        }
        return result;
    }
}
