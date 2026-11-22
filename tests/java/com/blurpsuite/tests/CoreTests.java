package com.blurpsuite.tests;

import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.blurpsuite.api.ExtensionHelpersImpl;
import com.blurpsuite.core.HttpParser;
import com.blurpsuite.core.Scope;
import com.blurpsuite.core.Service;
import com.blurpsuite.util.ByteUtil;
import com.blurpsuite.util.Json;

import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static com.blurpsuite.tests.TestRunner.check;
import static com.blurpsuite.tests.TestRunner.eq;
import static com.blurpsuite.tests.TestRunner.eqBytes;
import static com.blurpsuite.tests.TestRunner.throwsIllegalArgument;

/** Tests for the dependency-free HTTP parser, scope model and JSON codec. */
public final class CoreTests {

    public void testByteUtilRoundTrip() {
        byte[] bytes = ByteUtil.toBytes("caf\u00e9");
        eq(ByteUtil.toString(bytes), "caf\u00e9", "ISO-8859-1 round trip");
        eqBytes(ByteUtil.concat(ByteUtil.toBytes("ab"), ByteUtil.toBytes("cd")),
                ByteUtil.toBytes("abcd"), "concat");
    }

    public void testByteUtilIndexOfCaseInsensitive() {
        byte[] haystack = ByteUtil.toBytes("Host: Example.COM\r\n");
        check(ByteUtil.indexOf(haystack, ByteUtil.toBytes("example.com"), false, 0, haystack.length) == 6,
                "case-insensitive indexOf");
        check(ByteUtil.indexOf(haystack, ByteUtil.toBytes("example.com"), true, 0, haystack.length) == -1,
                "case-sensitive indexOf");
    }

    public void testByteUtilCopyOfRangeClamps() {
        byte[] data = ByteUtil.toBytes("abcd");
        eqBytes(ByteUtil.copyOfRange(data, -4, 2), ByteUtil.toBytes("ab"), "clamp low");
        eqBytes(ByteUtil.copyOfRange(data, 2, 99), ByteUtil.toBytes("cd"), "clamp high");
    }

    public void testBodyOffsetCrLfAndLf() {
        eq(HttpParser.bodyOffset(ByteUtil.toBytes("GET / HTTP/1.1\r\nHost: a\r\n\r\nbody")), 27,
                "CRLFCRLF body offset");
        eq(HttpParser.bodyOffset(ByteUtil.toBytes("GET / HTTP/1.1\nHost: a\n\nbody")), 24,
                "LFLF body offset");
    }

    public void testStartLineAndHeader() {
        byte[] request = ByteUtil.toBytes("POST /submit?a=1 HTTP/1.1\r\nHost: example.org\r\n"
                + "X-Test: yes\r\n\r\nbody");
        eq(ArraysToString(HttpParser.startLine(request)), "POST|/submit?a=1|HTTP/1.1", "start line");
        eq(HttpParser.header(request, "host"), "example.org", "case-insensitive header lookup");
        eq(HttpParser.header(request, "x-test"), "yes", "second header lookup");
        check(HttpParser.header(request, "missing") == null, "missing header is null");
    }

    public void testResolveService() {
        byte[] absolute = ByteUtil.toBytes("GET https://example.net:8443/a HTTP/1.1\r\n\r\n");
        Service absoluteService = HttpParser.resolveService(absolute, null);
        eq(absoluteService.getHost(), "example.net", "absolute URL host");
        eq(absoluteService.getPort(), 8443, "absolute URL port");
        eq(absoluteService.getProtocol(), "https", "absolute URL protocol");

        byte[] relative = ByteUtil.toBytes("GET /a HTTP/1.1\r\nHost: example.org:8080\r\n\r\n");
        Service relativeService = HttpParser.resolveService(relative, new Service("fallback", 80, "http"));
        eq(relativeService.getHost(), "example.org", "Host host");
        eq(relativeService.getPort(), 8080, "Host port");
    }

    public void testRequestUrl() {
        byte[] request = ByteUtil.toBytes("GET /path?q=1 HTTP/1.1\r\nHost: example.org:8080\r\n\r\n");
        eq(HttpParser.requestUrl(request, new Service("example.org", 8080, "http")).toExternalForm(),
                "http://example.org:8080/path?q=1", "request URL");
    }

    public void testAnalyzeRequestQueryAndForm() {
        byte[] request = ByteUtil.toBytes("POST /submit?a=1&b=two HTTP/1.1\r\n"
                + "Host: example.org\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                + "\r\nx=3&y=hello%20world");
        IRequestInfo info = new ExtensionHelpersImpl().analyzeRequest(request);
        eq(info.getMethod(), "POST", "method");
        eq((int) info.getContentType(), (int) IRequestInfo.CONTENT_TYPE_URL_ENCODED, "content type");
        eq(info.getParameters().size(), 4, "parameter count");
        eq(parameterMap(info).get("a"), "1", "query parameter a");
        eq(parameterMap(info).get("y"), "hello world", "form decoded parameter");
    }

    public void testJsonBodyParameters() {
        byte[] request = ByteUtil.toBytes("POST /api HTTP/1.1\r\nHost: example.org\r\n"
                + "Content-Type: application/json\r\n\r\n{\"name\": \"value\", \"n\": 2}");
        IRequestInfo info = new ExtensionHelpersImpl().analyzeRequest(request);
        eq((int) info.getContentType(), (int) IRequestInfo.CONTENT_TYPE_JSON, "json content type");
        Map<String, String> params = parameterMap(info);
        eq(params.get("name"), "value", "json string parameter");
        eq(params.get("n"), "2", "json number parameter");
    }

    public void testAnalyzeResponseCookiesAndMime() {
        byte[] response = ByteUtil.toBytes("HTTP/1.1 200 OK\r\n"
                + "Set-Cookie: sid=abc; Path=/; HttpOnly\r\n"
                + "Content-Type: text/html; charset=utf-8\r\n\r\n<html>ok</html>");
        IResponseInfo info = new ExtensionHelpersImpl().analyzeResponse(response);
        eq(info.getStatusCode(), (short) 200, "status code");
        eq(info.getStatedMimeType(), "text/html", "stated mime type");
        eq(info.getCookies().size(), 1, "cookie count");
        eq(info.getCookies().get(0).getName(), "sid", "cookie name");
        eq(info.getCookies().get(0).getValue(), "abc", "cookie value");
        eq(info.getCookies().get(0).getPath(), "/", "cookie path");
    }

    public void testInferMimeType() {
        IResponseInfo html = new ExtensionHelpersImpl().analyzeResponse(
                ByteUtil.toBytes("HTTP/1.1 200 OK\r\n\r\n<!doctype html><html>x</html>"));
        eq(html.getInferredMimeType(), "HTML", "inferred HTML");
        IResponseInfo json = new ExtensionHelpersImpl().analyzeResponse(
                ByteUtil.toBytes("HTTP/1.1 200 OK\r\n\r\n{\"a\":1}"));
        eq(json.getInferredMimeType(), "JSON", "inferred JSON");
    }

    public void testScopeRules() throws Exception {
        Scope scope = new Scope();
        AtomicInteger changes = new AtomicInteger();
        scope.addChangeListener(changes::incrementAndGet);

        scope.include("http://example.org");
        check(scope.isInScope(new URL("http://example.org/a")), "included host");
        check(!scope.isInScope(new URL("http://other.org/a")), "other host excluded");
        eq(changes.get(), 1, "one change event");
        scope.include("http://example.org");
        eq(changes.get(), 1, "duplicate include does not fire");

        scope.exclude("http://example.org/admin");
        check(!scope.isInScope(new URL("http://example.org/admin")), "exclude wins");
        check(scope.isInScope(new URL("http://example.org/home")), "include still applies");

        scope.clear();
        check(scope.isInScope(new URL("http://anything.test/")), "empty scope includes all");
    }

    public void testScopeWildcardSubdomain() throws Exception {
        Scope scope = new Scope();
        scope.include("*.example.org");
        check(scope.isInScope(new URL("http://api.example.org/")), "wildcard matches subdomain");
        check(scope.isInScope(new URL("http://example.org/")), "wildcard matches apex");
        check(!scope.isInScope(new URL("http://example.com/")), "wildcard rejects other domain");
    }

    public void testScopeHostSuffixBoundary() throws Exception {
        Scope exact = new Scope();
        exact.include("http://example.org");
        check(!exact.isInScope(new URL("http://evil-example.org/")),
                "exact rule rejects hyphen lookalike");
        check(!exact.isInScope(new URL("http://notexample.org/")),
                "exact rule rejects suffix lookalike");
        check(!exact.isInScope(new URL("http://example.org.attacker.test/")),
                "exact rule rejects lookalike parent domain");
        check(exact.isInScope(new URL("http://example.org/home")),
                "exact rule still matches the real host");

        Scope wildcard = new Scope();
        wildcard.include("*.example.org");
        check(!wildcard.isInScope(new URL("http://evil-example.org/")),
                "wildcard rejects hyphen lookalike");
        check(!wildcard.isInScope(new URL("http://notexample.org/")),
                "wildcard rejects suffix lookalike");
        check(wildcard.isInScope(new URL("http://api.example.org/")),
                "wildcard still matches a real subdomain");
        check(wildcard.isInScope(new URL("http://a.b.example.org/")),
                "wildcard still matches nested subdomains");
    }

    public void testJsonRoundTrip() {
        Map<String, Object> object = Json.obj();
        object.put("text", "line\n\"quoted\"");
        object.put("count", 7L);
        object.put("ok", true);
        object.put("nothing", null);
        object.put("items", List.of("a", "b"));

        String encoded = Json.write(object);
        Object decoded = Json.parse(encoded);
        check(decoded instanceof Map<?, ?>, "decoded object is a map");
        Map<?, ?> map = (Map<?, ?>) decoded;
        eq(map.get("text"), "line\n\"quoted\"", "escaped string round trip");
        eq(map.get("count"), 7L, "integer round trip");
        eq(map.get("ok"), Boolean.TRUE, "boolean round trip");
        check(map.get("nothing") == null, "null round trip");
        eq(map.get("items"), List.of("a", "b"), "array round trip");
    }

    public void testJsonUnicodeEscapes() {
        eq(Json.parse("\"\\u00e9\""), "\u00e9", "unicode escape");
        eq(Json.parse("\"a\\tb\""), "a\tb", "tab escape");
        throwsIllegalArgument(() -> Json.parse("{\"a\":1} trailing"), "trailing characters");
        throwsIllegalArgument(() -> Json.parse("{\"a\" 1}"), "missing colon");
    }

    public void testJsonAccessors() {
        eq(Json.string("x", "fallback"), "x", "string accessor");
        eq(Json.string(42, "fallback"), "fallback", "string accessor fallback");
        eq(Json.integer(9L, -1), 9, "integer accessor");
        eq(Json.integer("9", -1), -1, "integer accessor fallback");
    }

    private static Map<String, String> parameterMap(IRequestInfo info) {
        Map<String, String> result = new java.util.LinkedHashMap<>();
        for (IParameter parameter : info.getParameters()) {
            result.put(parameter.getName(), parameter.getValue());
        }
        return result;
    }

    private static String ArraysToString(String[] values) {
        return String.join("|", values);
    }
}
