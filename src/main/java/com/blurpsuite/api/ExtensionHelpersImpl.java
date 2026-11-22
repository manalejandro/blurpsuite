package com.blurpsuite.api;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScannerInsertionPoint;
import com.blurpsuite.core.HttpParser;
import com.blurpsuite.core.Service;
import com.blurpsuite.util.ByteUtil;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/** Working implementation of the extension helper surface. */
public final class ExtensionHelpersImpl implements IExtensionHelpers {
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    @Override
    public IRequestInfo analyzeRequest(byte[] request) {
        return HttpParser.analyzeRequest(request, HttpParser.resolveService(request, null), null);
    }

    @Override
    public IRequestInfo analyzeRequest(IHttpRequestResponse request) {
        return HttpParser.analyzeRequest(request.getRequest(), request.getHttpService(), request);
    }

    @Override
    public IRequestInfo analyzeRequest(IHttpService httpService, byte[] request) {
        return HttpParser.analyzeRequest(request, httpService, null);
    }

    @Override
    public IResponseInfo analyzeResponse(byte[] response) {
        return HttpParser.analyzeResponse(response);
    }

    @Override
    public burp.IResponseKeywords analyzeResponseKeywords(List<String> keywords, byte[]... responses) {
        return new ResponseKeywordsImpl(keywords, responses);
    }

    @Override
    public burp.IResponseVariations analyzeResponseVariations(byte[]... responses) {
        return new ResponseVariationsImpl(responses);
    }

    @Override
    public byte[] base64Decode(byte[] data) {
        return Base64.getDecoder().decode(data);
    }

    @Override
    public byte[] base64Decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    @Override
    public String base64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    @Override
    public String base64Encode(String data) {
        return base64Encode(data.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public burp.IHttpHeader buildHeader(String name, String value) {
        return new HttpHeaderImpl(name, value);
    }

    @Override
    public byte[] buildHttpMessage(List<String> headers, byte[] body) {
        StringBuilder message = new StringBuilder();
        for (String header : headers) {
            message.append(header).append("\r\n");
        }
        message.append("\r\n");
        return ByteUtil.concat(ByteUtil.toBytes(message.toString()), body == null ? new byte[0] : body);
    }

    @Override
    public byte[] buildHttpRequest(URL url) {
        String path = url.getPath() == null || url.getPath().isEmpty() ? "/" : url.getPath();
        if (url.getQuery() != null) {
            path += "?" + url.getQuery();
        }
        int port = url.getPort() >= 0 ? url.getPort() : ("https".equals(url.getProtocol()) ? 443 : 80);
        String authority = url.getHost() + ((port == 80 || port == 443) ? "" : ":" + port);
        return ByteUtil.toBytes("GET " + path + " HTTP/1.1\r\nHost: " + authority
                + "\r\nUser-Agent: Blurp Suite\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    }

    @Override
    public IHttpService buildHttpService(String host, int port, boolean useHttps) {
        return new Service(host, port, useHttps ? "https" : "http");
    }

    @Override
    public IHttpService buildHttpService(String host, int port, String protocol) {
        return new Service(host, port, protocol);
    }

    @Override
    public IParameter buildParameter(String name, String value, byte type) {
        return new ParameterImpl(name, value, type, -1, -1, -1, -1);
    }

    @Override
    public String bytesToString(byte[] data) {
        return ByteUtil.toString(data);
    }

    @Override
    public IParameter getRequestParameter(byte[] request, String parameterName) {
        for (IParameter parameter : analyzeRequest(request).getParameters()) {
            if (parameter.getName().equals(parameterName)) {
                return parameter;
            }
        }
        return null;
    }

    @Override
    public int indexOf(byte[] data, byte[] pattern, boolean caseSensitive, int from, int to) {
        return ByteUtil.indexOf(data, pattern, caseSensitive, from, to);
    }

    @Override
    public IScannerInsertionPoint makeScannerInsertionPoint(String name, byte[] baseRequest, int from, int to) {
        return new ScannerInsertionPointImpl(name, baseRequest, from, to,
                IScannerInsertionPoint.INS_USER_PROVIDED);
    }

    @Override
    public byte[] addParameter(byte[] request, IParameter parameter) {
        String text = ByteUtil.toString(request);
        int headerEnd = headerEndIndex(text);
        String head = text.substring(0, headerEnd);
        String body = text.substring(headerEnd);
        String encoded = urlEncode(parameter.getName()) + "=" + urlEncode(parameter.getValue());

        if (parameter.getType() == IParameter.PARAM_URL) {
            int lineEnd = head.indexOf('\n');
            String firstLine = head.substring(0, lineEnd).replace("\r", "");
            String remainder = head.substring(lineEnd);
            firstLine += (firstLine.contains("?") ? "&" : "?") + encoded;
            return ByteUtil.toBytes(firstLine + remainder + body);
        }
        if (parameter.getType() == IParameter.PARAM_COOKIE) {
            String cookieHeader = HttpParser.header(request, "Cookie");
            if (cookieHeader == null) {
                head = insertHeader(head, "Cookie: " + encoded);
            } else {
                head = head.replaceFirst("(?i)(Cookie:)([^\\r\\n]*)", "$1" + encoded + "; $2");
            }
            return ByteUtil.toBytes(head + body);
        }
        String newBody = body.isEmpty() ? encoded : body + "&" + encoded;
        head = updateContentLength(head, ByteUtil.toBytes(newBody).length);
        return ByteUtil.toBytes(head + newBody);
    }

    @Override
    public byte[] updateParameter(byte[] request, IParameter parameter) {
        return replaceParameter(request, parameter, urlEncode(parameter.getValue()));
    }

    @Override
    public byte[] removeParameter(byte[] request, IParameter parameter) {
        return replaceParameter(request, parameter, "");
    }

    @Override
    public byte[] stringToBytes(String data) {
        return ByteUtil.toBytes(data);
    }

    @Override
    public byte[] toggleRequestMethod(byte[] request) {
        String text = ByteUtil.toString(request);
        int lineEnd = text.indexOf('\n');
        if (lineEnd < 0) {
            return request;
        }
        String firstLine = text.substring(0, lineEnd).replace("\r", "");
        String[] parts = firstLine.split("\\s+", 3);
        if (parts.length < 2) {
            return request;
        }
        boolean toPost = parts[0].equalsIgnoreCase("GET");
        parts[0] = toPost ? "POST" : "GET";
        String head = parts[0] + " " + parts[1] + " " + (parts.length > 2 ? parts[2] : "HTTP/1.1")
                + text.substring(lineEnd);
        int headerEnd = headerEndIndex(head);
        String headers = head.substring(0, headerEnd);
        String body = head.substring(headerEnd);
        if (toPost) {
            headers = updateContentLength(headers, body.length());
            if (!headers.toLowerCase(Locale.ROOT).contains("content-type:")) {
                headers = insertHeader(headers, "Content-Type: application/x-www-form-urlencoded");
            }
        } else {
            headers = headers.replaceAll("(?im)^(Content-Length|Content-Type):.*\\r?\\n?", "");
        }
        return ByteUtil.toBytes(headers + body);
    }

    @Override
    public byte[] urlDecode(byte[] data) {
        return ByteUtil.toBytes(urlDecode(ByteUtil.toString(data)));
    }

    @Override
    public String urlDecode(String data) {
        try {
            return java.net.URLDecoder.decode(data, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return data;
        }
    }

    @Override
    public byte[] urlEncode(byte[] data) {
        return ByteUtil.toBytes(urlEncode(ByteUtil.toString(data)));
    }

    @Override
    public String urlEncode(String data) {
        StringBuilder encoded = new StringBuilder();
        for (byte value : data.getBytes(StandardCharsets.UTF_8)) {
            int c = value & 0xFF;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~') {
                encoded.append((char) c);
            } else {
                encoded.append('%').append(HEX[c >> 4]).append(HEX[c & 0x0F]);
            }
        }
        return encoded.toString();
    }

    private static byte[] replaceParameter(byte[] request, IParameter parameter, String replacement) {
        if (parameter.getValueStart() < 0 || parameter.getValueEnd() > request.length) {
            return request;
        }
        byte[] prefix = ByteUtil.copyOfRange(request, 0, parameter.getValueStart());
        byte[] suffix = ByteUtil.copyOfRange(request, parameter.getValueEnd(), request.length);
        byte[] result = ByteUtil.concat(ByteUtil.concat(prefix, ByteUtil.toBytes(replacement)), suffix);
        String text = ByteUtil.toString(result);
        int headerEnd = headerEndIndex(text);
        String head = updateContentLength(text.substring(0, headerEnd),
                ByteUtil.toBytes(text.substring(headerEnd)).length);
        return ByteUtil.toBytes(head + text.substring(headerEnd));
    }

    private static int headerEndIndex(String text) {
        int index = text.indexOf("\r\n\r\n");
        if (index >= 0) {
            return index + 4;
        }
        index = text.indexOf("\n\n");
        return index >= 0 ? index + 2 : text.length();
    }

    private static String insertHeader(String headers, String header) {
        String separator = headers.endsWith("\r\n") ? "" : "\r\n";
        int firstLineEnd = headers.indexOf('\n');
        if (firstLineEnd < 0) {
            return headers + separator + header + "\r\n";
        }
        return headers.substring(0, firstLineEnd + 1) + header + "\r\n"
                + headers.substring(firstLineEnd + 1);
    }

    private static String updateContentLength(String headers, int bodyLength) {
        if (!headers.toLowerCase(Locale.ROOT).contains("content-length:")) {
            return headers;
        }
        return headers.replaceAll("(?im)^(Content-Length:)\\s*\\d+", "$1 " + bodyLength);
    }
}
