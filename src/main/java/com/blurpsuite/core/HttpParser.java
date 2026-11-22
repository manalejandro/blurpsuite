package com.blurpsuite.core;

import burp.ICookie;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.blurpsuite.api.CookieImpl;
import com.blurpsuite.api.ParameterImpl;
import com.blurpsuite.api.RequestInfoImpl;
import com.blurpsuite.api.ResponseInfoImpl;
import com.blurpsuite.util.ByteUtil;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/** Dependency-free HTTP/1.x message parser used by the proxy and the Extender helpers. */
public final class HttpParser {
    private HttpParser() {
    }

    /** Returns the offset of the first byte after the header block. */
    public static int bodyOffset(byte[] message) {
        byte[] crlfcrlf = {'\r', '\n', '\r', '\n'};
        int index = ByteUtil.indexOf(message, crlfcrlf, false, 0, message.length);
        if (index >= 0) {
            return index + 4;
        }
        byte[] lflf = {'\n', '\n'};
        index = ByteUtil.indexOf(message, lflf, false, 0, message.length);
        return index >= 0 ? index + 2 : message.length;
    }

    /** Returns the start line as up to three tokens. */
    public static String[] startLine(byte[] message) {
        String text = ByteUtil.toString(message);
        int end = text.indexOf('\n');
        String line = (end < 0 ? text : text.substring(0, end)).replace("\r", "").trim();
        return line.split("\\s+", 3);
    }

    /** Returns header lines without the terminating CRLF. */
    public static List<String> headerLines(byte[] message) {
        int offset = bodyOffset(message);
        String headerBlock = ByteUtil.toString(message).substring(0, Math.min(offset, message.length));
        String[] lines = headerBlock.split("\\r?\\n");
        List<String> headers = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            if (!lines[i].isBlank()) {
                headers.add(lines[i]);
            }
        }
        return headers;
    }

    /** Returns the value of the first header with the given name, or null. */
    public static String header(byte[] message, String name) {
        for (String line : headerLines(message)) {
            int separator = line.indexOf(':');
            if (separator > 0 && line.substring(0, separator).trim().equalsIgnoreCase(name)) {
                return line.substring(separator + 1).trim();
            }
        }
        return null;
    }

    /** Resolves the upstream service from an absolute request target or the Host header. */
    public static Service resolveService(byte[] request, Service fallback) {
        String[] line = startLine(request);
        String target = line.length > 1 ? line[1] : "/";
        if (target.startsWith("http://") || target.startsWith("https://")) {
            try {
                URL url = new URL(target);
                return new Service(url.getHost(), url.getPort() >= 0 ? url.getPort()
                        : ("https".equals(url.getProtocol()) ? 443 : 80), url.getProtocol());
            } catch (MalformedURLException ignored) {
                // Fall through to the Host header.
            }
        }
        String host = header(request, "Host");
        if (host == null || host.isBlank()) {
            return fallback;
        }
        boolean secure = fallback != null && fallback.isSecure();
        int port = secure ? 443 : 80;
        String hostname = host;
        int colon = host.lastIndexOf(':');
        if (colon > 0 && host.substring(colon + 1).chars().allMatch(Character::isDigit)) {
            hostname = host.substring(0, colon);
            port = Integer.parseInt(host.substring(colon + 1));
        }
        return new Service(hostname, port, secure ? "https" : "http");
    }

    /** Builds the absolute URL represented by a request. */
    public static URL requestUrl(byte[] request, IHttpService service) {
        String[] line = startLine(request);
        String target = line.length > 1 ? line[1] : "/";
        try {
            if (target.startsWith("http://") || target.startsWith("https://")) {
                return new URL(target);
            }
            String protocol = service != null ? service.getProtocol() : "http";
            String host = service != null ? service.getHost() : "localhost";
            int port = service != null ? service.getPort() : 80;
            String authority = host;
            if ((protocol.equals("http") && port != 80) || (protocol.equals("https") && port != 443)) {
                authority += ":" + port;
            }
            return new URL(protocol + "://" + authority + (target.startsWith("/") ? target : "/" + target));
        } catch (MalformedURLException e) {
            try {
                return new URL("http://invalid.local/");
            } catch (MalformedURLException impossible) {
                throw new IllegalStateException(impossible);
            }
        }
    }

    public static IRequestInfo analyzeRequest(byte[] request, IHttpService service,
                                              IHttpRequestResponse message) {
        String[] line = startLine(request);
        String method = line.length > 0 ? line[0] : "GET";
        List<String> headers = headerLines(request);
        List<IParameter> parameters = new ArrayList<>();
        int body = bodyOffset(request);

        String[] target = (line.length > 1 ? line[1] : "/").split("\\?", 2);
        if (target.length == 2) {
            int queryStart = ByteUtil.indexOf(request, ByteUtil.toBytes("?"), false, 0, body);
            parseUrlEncoded(request, queryStart + 1, body, IParameter.PARAM_URL, parameters);
        }
        parseFormParameters(request, body, request.length, parameters);

        String contentType = header(request, "Content-Type");
        return new RequestInfoImpl(method, requestUrl(request, service), headers, parameters,
                body, contentTypeByte(contentType), message);
    }

    public static IResponseInfo analyzeResponse(byte[] response) {
        String[] line = startLine(response);
        short status = 0;
        if (line.length > 1) {
            try {
                status = Short.parseShort(line[1]);
            } catch (NumberFormatException ignored) {
                status = 0;
            }
        }
        List<String> headers = headerLines(response);
        List<ICookie> cookies = new ArrayList<>();
        for (String header : headers) {
            int separator = header.indexOf(':');
            if (separator <= 0 || !header.substring(0, separator).trim().equalsIgnoreCase("Set-Cookie")) {
                continue;
            }
            cookies.add(parseCookie(header.substring(separator + 1).trim()));
        }
        String stated = header(response, "Content-Type");
        if (stated != null && stated.indexOf(';') > 0) {
            stated = stated.substring(0, stated.indexOf(';')).trim();
        }
        byte[] body = ByteUtil.copyOfRange(response, bodyOffset(response), response.length);
        return new ResponseInfoImpl(status, headers, cookies, bodyOffset(response),
                stated == null ? "" : stated, inferMimeType(body, stated));
    }

    /** Returns request parameters as {name, value} rows, matching the Extender API shape. */
    public static String[][] parameterRows(byte[] request) {
        List<IParameter> parameters = analyzeRequest(request, null, null).getParameters();
        String[][] rows = new String[parameters.size()][2];
        for (int i = 0; i < parameters.size(); i++) {
            rows[i][0] = parameters.get(i).getName();
            rows[i][1] = parameters.get(i).getValue();
        }
        return rows;
    }

    private static void parseFormParameters(byte[] request, int from, int to, List<IParameter> parameters) {
        String contentType = header(request, "Content-Type");
        if (contentType != null && contentType.toLowerCase(Locale.ROOT).contains("application/x-www-form-urlencoded")) {
            parseUrlEncoded(request, from, to, IParameter.PARAM_BODY, parameters);
        } else if (contentType != null && contentType.toLowerCase(Locale.ROOT).contains("application/json")) {
            parseJson(request, from, to, parameters);
        } else if (contentType != null && contentType.toLowerCase(Locale.ROOT).contains("xml")) {
            parseXml(request, from, to, parameters);
        }
    }

    private static void parseUrlEncoded(byte[] data, int from, int to, byte type, List<IParameter> parameters) {
        if (from < 0 || from >= to) {
            return;
        }
        int segmentStart = from;
        for (int i = from; i <= to; i++) {
            if (i != to && data[i] != '&') {
                continue;
            }
            int equals = -1;
            for (int j = segmentStart; j < i; j++) {
                if (data[j] == '=') {
                    equals = j;
                    break;
                }
            }
            if (equals > segmentStart) {
                String name = decode(data, segmentStart, equals);
                String value = decode(data, equals + 1, i);
                parameters.add(new ParameterImpl(name, value, type,
                        segmentStart, equals, equals + 1, i));
            }
            segmentStart = i + 1;
        }
    }

    private static void parseJson(byte[] data, int from, int to, List<IParameter> parameters) {
        // Lightweight top-level "key": "value" extraction; sufficient for helper-based
        // parameter lookup in typical JSON request bodies.
        boolean inString = false;
        boolean escaped = false;
        int keyStart = -1;
        int keyEnd = -1;
        for (int i = from; i < to; i++) {
            char c = (char) (data[i] & 0xFF);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\' && inString) {
                escaped = true;
                continue;
            }
            if (c == '"') {
                if (inString) {
                    if (keyStart >= 0 && keyEnd < 0) {
                        keyEnd = i;
                    }
                    inString = false;
                } else {
                    inString = true;
                    if (keyStart < 0) {
                        keyStart = i;
                    }
                }
                continue;
            }
            if (!inString && keyStart >= 0 && keyEnd >= 0 && c == ':') {
                String name = decode(data, keyStart + 1, keyEnd);
                int p = i + 1;
                while (p < to && Character.isWhitespace((char) (data[p] & 0xFF))) {
                    p++;
                }
                int valueStart = p;
                int valueEnd;
                if (p < to && data[p] == '"') {
                    p++;
                    valueStart = p;
                    while (p < to) {
                        if (data[p] == '\\' && p + 1 < to) {
                            p += 2;
                            continue;
                        }
                        if (data[p] == '"') {
                            break;
                        }
                        p++;
                    }
                    valueEnd = Math.min(p, to);
                    i = valueEnd;
                } else {
                    while (p < to && data[p] != ',' && data[p] != '}') {
                        p++;
                    }
                    valueEnd = p;
                    i = Math.max(i, p - 1);
                }
                String value = decode(data, valueStart, valueEnd);
                parameters.add(new ParameterImpl(name, value, IParameter.PARAM_JSON,
                        keyStart + 1, keyEnd, valueStart, valueEnd));
                keyStart = -1;
                keyEnd = -1;
            }
        }
    }

    private static void parseXml(byte[] data, int from, int to, List<IParameter> parameters) {
        for (int i = from; i < to - 1; i++) {
            if (data[i] != '<' || data[i + 1] == '/' || data[i + 1] == '?' || data[i + 1] == '!') {
                continue;
            }
            int tagEnd = i + 1;
            while (tagEnd < to && data[tagEnd] != '>' && data[tagEnd] != ' ') {
                tagEnd++;
            }
            int closeTag = tagEnd;
            while (closeTag < to && data[closeTag] != '>') {
                closeTag++;
            }
            int openEnd = closeTag < to ? closeTag + 1 : to;
            byte[] closing = ByteUtil.toBytes("</" + new String(data, i + 1, tagEnd - i - 1,
                    StandardCharsets.ISO_8859_1) + ">");
            int valueEnd = ByteUtil.indexOf(data, closing, true, openEnd, to);
            if (valueEnd > openEnd) {
                String name = new String(data, i + 1, tagEnd - i - 1, StandardCharsets.ISO_8859_1);
                String value = new String(data, openEnd, valueEnd - openEnd, StandardCharsets.ISO_8859_1);
                parameters.add(new ParameterImpl(name, value, IParameter.PARAM_XML,
                        i + 1, tagEnd, openEnd, valueEnd));
                i = valueEnd + closing.length - 1;
            }
        }
    }

    private static String decode(byte[] data, int from, int to) {
        if (from < 0 || to > data.length || from >= to) {
            return "";
        }
        String raw = new String(data, from, to - from, StandardCharsets.ISO_8859_1).trim();
        try {
            return URLDecoder.decode(raw, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return raw;
        }
    }

    private static CookieImpl parseCookie(String setCookie) {
        String[] parts = setCookie.split(";");
        String name = "";
        String value = "";
        if (parts.length > 0) {
            int equals = parts[0].indexOf('=');
            if (equals > 0) {
                name = parts[0].substring(0, equals).trim();
                value = parts[0].substring(equals + 1).trim();
            }
        }
        String domain = "";
        String path = "";
        Date expiration = null;
        for (int i = 1; i < parts.length; i++) {
            String part = parts[i].trim();
            int equals = part.indexOf('=');
            if (equals <= 0) {
                continue;
            }
            String key = part.substring(0, equals).trim();
            String val = part.substring(equals + 1).trim();
            if (key.equalsIgnoreCase("Domain")) {
                domain = val;
            } else if (key.equalsIgnoreCase("Path")) {
                path = val;
            } else if (key.equalsIgnoreCase("Expires")) {
                expiration = parseDate(val);
            }
        }
        return new CookieImpl(domain, expiration, name, path, value);
    }

    private static Date parseDate(String value) {
        String[] patterns = {"EEE, dd MMM yyyy HH:mm:ss zzz", "EEE, dd-MMM-yy HH:mm:ss zzz"};
        for (String pattern : patterns) {
            try {
                return new SimpleDateFormat(pattern, Locale.US).parse(value);
            } catch (ParseException ignored) {
                // Try the next supported cookie date format.
            }
        }
        return null;
    }

    private static byte contentTypeByte(String contentType) {
        if (contentType == null || contentType.isBlank()) {
            return IRequestInfo.CONTENT_TYPE_NONE;
        }
        String value = contentType.toLowerCase(Locale.ROOT);
        if (value.contains("x-www-form-urlencoded")) {
            return IRequestInfo.CONTENT_TYPE_URL_ENCODED;
        }
        if (value.contains("multipart/form-data")) {
            return IRequestInfo.CONTENT_TYPE_MULTIPART;
        }
        if (value.contains("xml")) {
            return IRequestInfo.CONTENT_TYPE_XML;
        }
        if (value.contains("json")) {
            return IRequestInfo.CONTENT_TYPE_JSON;
        }
        if (value.contains("amf")) {
            return IRequestInfo.CONTENT_TYPE_AMF;
        }
        return IRequestInfo.CONTENT_TYPE_UNKNOWN;
    }

    private static String inferMimeType(byte[] body, String stated) {
        if (stated != null && !stated.isBlank()) {
            return stated;
        }
        String compact = ByteUtil.toString(body).replaceAll("\\s+", "");
        String prefix = compact.substring(0, Math.min(256, compact.length()));
        String lower = prefix.toLowerCase(Locale.ROOT);
        if (lower.startsWith("<!doctypehtml") || lower.startsWith("<html")) {
            return "HTML";
        }
        if (lower.startsWith("<?xml") || lower.startsWith("<rss") || lower.startsWith("<svg")) {
            return "XML";
        }
        if (lower.startsWith("{") || lower.startsWith("[")) {
            return "JSON";
        }
        if (lower.startsWith("function") || lower.contains("var ")) {
            return "SCRIPT";
        }
        return "UNKNOWN";
    }
}
