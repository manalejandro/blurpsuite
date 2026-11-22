package com.blurpsuite.tests;

import com.blurpsuite.extensions.JrpcConnection;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static com.blurpsuite.tests.TestRunner.check;
import static com.blurpsuite.tests.TestRunner.eq;

/** Tests JSON-RPC notifications that carry no request id. */
public final class JrpcConnectionTests {

    public void testNoIdNotificationDispatchedWithoutReply() throws Exception {
        assertNotificationDispatchedWithoutReply(
                "{\"method\":\"printOutput\",\"params\":{\"message\":\"hello\"}}\n");
    }

    public void testNullIdNotificationDispatchedWithoutReply() throws Exception {
        assertNotificationDispatchedWithoutReply(
                "{\"id\":null,\"method\":\"printOutput\",\"params\":{\"message\":\"hello\"}}\n");
    }

    private static void assertNotificationDispatchedWithoutReply(String notification) throws Exception {
        String frames = notification + "{\"id\":42,\"method\":\"ping\",\"params\":{}}\n";
        ByteArrayOutputStream written = new ByteArrayOutputStream();
        AtomicInteger notifications = new AtomicInteger();
        AtomicReference<String> message = new AtomicReference<>();
        FakeProcess process = new FakeProcess(
                new ByteArrayInputStream(frames.getBytes(StandardCharsets.UTF_8)), written);
        JrpcConnection connection = new JrpcConnection(process, (method, params) -> {
            if ("printOutput".equals(method)) {
                notifications.incrementAndGet();
                message.set(String.valueOf(params.get("message")));
            }
            return "ok";
        });
        try {
            String output = awaitReply(written);
            check(output.contains("\"id\":42"), "reply carries the request id");
            eq(notifications.get(), 1, "notification handler ran");
            eq(message.get(), "hello", "notification params delivered");
            eq(output.lines().count(), 1L, "no reply frame written for notification");
            check(!output.contains("printOutput"), "notification method not echoed back");
        } finally {
            connection.close();
        }
    }

    private static String awaitReply(ByteArrayOutputStream written) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            String text = written.toString(StandardCharsets.UTF_8);
            if (text.contains("\"id\":42")) {
                return text;
            }
            Thread.sleep(10);
        }
        throw new AssertionError("no reply frame received from JrpcConnection");
    }

    private static final class FakeProcess extends Process {
        private final InputStream input;
        private final OutputStream output;

        FakeProcess(InputStream input, OutputStream output) {
            this.input = input;
            this.output = output;
        }

        @Override
        public OutputStream getOutputStream() {
            return output;
        }

        @Override
        public InputStream getInputStream() {
            return input;
        }

        @Override
        public InputStream getErrorStream() {
            return new ByteArrayInputStream(new byte[0]);
        }

        @Override
        public int waitFor() {
            return 0;
        }

        @Override
        public int exitValue() {
            return 0;
        }

        @Override
        public void destroy() {
            // Nothing to destroy in the fake process.
        }
    }
}
