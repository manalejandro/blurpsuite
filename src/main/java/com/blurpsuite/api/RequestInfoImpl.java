package com.blurpsuite.api;

import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;

import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Parsed view of an HTTP request. */
public final class RequestInfoImpl implements IRequestInfo {
    private final String method;
    private final URL url;
    private final List<String> headers;
    private final List<IParameter> parameters;
    private final int bodyOffset;
    private final byte contentType;
    private final IHttpRequestResponse message;

    public RequestInfoImpl(String method, URL url, List<String> headers, List<IParameter> parameters,
                           int bodyOffset, byte contentType, IHttpRequestResponse message) {
        this.method = method;
        this.url = url;
        this.headers = new ArrayList<>(headers);
        this.parameters = new ArrayList<>(parameters);
        this.bodyOffset = bodyOffset;
        this.contentType = contentType;
        this.message = message;
    }

    @Override
    public String getMethod() {
        return method;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public List<String> getHeaders() {
        return Collections.unmodifiableList(headers);
    }

    @Override
    public List<IParameter> getParameters() {
        return Collections.unmodifiableList(parameters);
    }

    @Override
    public int getBodyOffset() {
        return bodyOffset;
    }

    @Override
    public byte getContentType() {
        return contentType;
    }

    public IHttpRequestResponse getMessage() {
        return message;
    }
}
