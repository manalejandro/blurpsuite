package com.blurpsuite.tests;

import burp.IExtensionStateListener;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IParameter;
import burp.IProxyListener;
import burp.IScopeChangeListener;
import com.blurpsuite.api.ApiTrafficBridge;
import com.blurpsuite.api.BurpExtenderCallbacksImpl;
import com.blurpsuite.api.ExtensionHelpersImpl;
import com.blurpsuite.core.HttpExchange;
import com.blurpsuite.core.ProxyServer;
import com.blurpsuite.core.Service;
import com.blurpsuite.util.ByteUtil;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import static com.blurpsuite.tests.TestRunner.check;
import static com.blurpsuite.tests.TestRunner.eq;
import static com.blurpsuite.tests.TestRunner.eqBytes;

/** Tests for the Burp callback surface exposed to extensions. */
public final class ApiTests {

    private static BurpExtenderCallbacksImpl callbacks() {
        PrintStream out = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
        return new BurpExtenderCallbacksImpl(new ProxyServer(0, "127.0.0.1"),
                new String[]{"--extension-arg", "value"}, out, out);
    }

    public void testToolNames() {
        BurpExtenderCallbacksImpl callbacks = callbacks();
        eq(callbacks.getToolName(burp.IBurpExtenderCallbacks.TOOL_PROXY), "Proxy", "proxy tool name");
        eq(callbacks.getToolName(burp.IBurpExtenderCallbacks.TOOL_SCANNER), "Scanner", "scanner tool name");
        eq(callbacks.getToolName(9999), "Unknown", "unknown tool name");
        eq(callbacks.getBurpVersion()[0], "Blurp Suite", "product name");
    }

    public void testExtensionMetadata() {
        BurpExtenderCallbacksImpl callbacks = callbacks();
        callbacks.setExtensionName("Example");
        eq(callbacks.extensionName(), "Example", "extension name");
        callbacks.setExtensionFilename("example.jar");
        eq(callbacks.getExtensionFilename(), "example.jar", "extension filename");

        String[] args = callbacks.getCommandLineArguments();
        args[0] = "mutated";
        eq(callbacks.getCommandLineArguments()[0], "--extension-arg",
                "command line arguments are defensively copied");
    }

    public void testExtensionStateListener() {
        BurpExtenderCallbacksImpl callbacks = callbacks();
        AtomicInteger fired = new AtomicInteger();
        IExtensionStateListener listener = fired::incrementAndGet;
        callbacks.registerExtensionStateListener(listener);
        eq(callbacks.getExtensionStateListeners().size(), 1, "listener registered");
        callbacks.notifyExtensionStateListeners();
        eq(fired.get(), 1, "listener notified once");

        callbacks.removeExtensionStateListener(listener);
        callbacks.notifyExtensionStateListeners();
        eq(fired.get(), 1, "removed listener is not notified");

        IExtensionStateListener broken = () -> {
            throw new IllegalStateException("boom");
        };
        callbacks.registerExtensionStateListener(broken);
        callbacks.registerExtensionStateListener(fired::incrementAndGet);
        callbacks.notifyExtensionStateListeners();
        eq(fired.get(), 2, "one broken listener does not block the next");
    }

    public void testScopeChangeListener() throws Exception {
        BurpExtenderCallbacksImpl callbacks = callbacks();
        AtomicInteger fired = new AtomicInteger();
        IScopeChangeListener listener = fired::incrementAndGet;
        callbacks.registerScopeChangeListener(listener);
        callbacks.includeInScope(new URL("http://example.org"));
        eq(fired.get(), 1, "scope change notified");
        callbacks.includeInScope(new URL("http://other.org"));
        eq(fired.get(), 2, "second scope change notified");
        check(callbacks.isInScope(new URL("http://example.org/a")), "URL in scope");
    }

    public void testProxyListenerRegistration() {
        BurpExtenderCallbacksImpl callbacks = callbacks();
        IProxyListener listener = (messageIsRequest, message) -> { };
        callbacks.registerProxyListener(listener);
        eq(callbacks.getProxyListeners().size(), 1, "proxy listener registered");
        callbacks.removeProxyListener(listener);
        check(callbacks.getProxyListeners().isEmpty(), "proxy listener removed");
    }

    public void testProxyListenerRehookRerunsListeners() {
        BurpExtenderCallbacksImpl callbacks = callbacks();
        AtomicInteger calls = new AtomicInteger();
        IProxyListener listener = (messageIsRequest, message) -> {
            int pass = calls.incrementAndGet();
            message.getMessageInfo().setComment("pass-" + pass);
            if (pass == 1) {
                message.setInterceptAction(IInterceptedProxyMessage.ACTION_FOLLOW_RULES_AND_REHOOK);
            }
        };
        callbacks.registerProxyListener(listener);
        HttpExchange exchange = new HttpExchange(1L, ByteUtil.toBytes("GET / HTTP/1.1\r\n\r\n"),
                new Service("example.org", 80, "http"), "test", "");

        check(new ApiTrafficBridge(callbacks).onMessage(true, exchange), "rehook does not drop traffic");
        eq(calls.get(), 2, "rehook ran the proxy listener twice");
        eq(exchange.getComment(), "pass-2", "second listener pass sees the updated exchange");
    }

    public void testSiteMapAndCookieJar() {
        BurpExtenderCallbacksImpl callbacks = callbacks();
        HttpExchange exchange = new HttpExchange(1L, ByteUtil.toBytes("GET / HTTP/1.1\r\n\r\n"),
                new Service("example.org", 80, "http"), "test", "");
        callbacks.addToSiteMap(exchange);
        IHttpRequestResponse[] items = callbacks.getSiteMap("http://example.org");
        eq(items.length, 1, "site map item added");

        callbacks.updateCookieJar(new com.blurpsuite.api.CookieImpl("example.org", null,
                "sid", "/", "abc"));
        eq(callbacks.getCookieJarContents().size(), 1, "cookie jar updated");
    }

    public void testHelpersBasics() throws Exception {
        ExtensionHelpersImpl helpers = new ExtensionHelpersImpl();
        String encoded = helpers.base64Encode("hello");
        eq(encoded, "aGVsbG8=", "base64 encode");
        eqBytes(helpers.base64Decode(encoded), ByteUtil.toBytes("hello"), "base64 decode");

        byte[] message = helpers.buildHttpMessage(
                java.util.List.of("POST / HTTP/1.1", "Host: example.org"),
                ByteUtil.toBytes("body"));
        eq(ByteUtil.toString(message), "POST / HTTP/1.1\r\nHost: example.org\r\n\r\nbody",
                "buildHttpMessage");

        byte[] request = helpers.buildHttpRequest(new URL("https://example.org/a?q=1"));
        eq(ByteUtil.toString(request).split("\r\n")[0], "GET /a?q=1 HTTP/1.1", "buildHttpRequest");
        check(ByteUtil.toString(request).contains("Host: example.org"), "buildHttpRequest Host header");

        IParameter parameter = helpers.buildParameter("a", "b", IParameter.PARAM_URL);
        eq(parameter.getName(), "a", "buildParameter name");
        eq((int) parameter.getType(), (int) IParameter.PARAM_URL, "buildParameter type");

        eq(helpers.buildHttpService("example.org", 443, true).getProtocol(), "https",
                "buildHttpService https");
        eq(helpers.bytesToString(ByteUtil.toBytes("abc")), "abc", "bytesToString");
    }

    public void testHelpersAddParameter() {
        ExtensionHelpersImpl helpers = new ExtensionHelpersImpl();
        byte[] request = ByteUtil.toBytes("GET /?a=1 HTTP/1.1\r\nHost: example.org\r\n\r\n");
        byte[] updated = helpers.addParameter(request,
                helpers.buildParameter("b", "2", IParameter.PARAM_URL));
        String text = ByteUtil.toString(updated);
        check(text.contains("b=2"), "parameter added to query: " + text);
    }
}
