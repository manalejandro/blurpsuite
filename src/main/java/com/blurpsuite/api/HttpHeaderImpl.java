package com.blurpsuite.api;

import burp.IHttpHeader;

/** A single HTTP header name/value pair. */
public final class HttpHeaderImpl implements IHttpHeader {
    private final String name;
    private final String value;

    public HttpHeaderImpl(String name, String value) {
        this.name = name;
        this.value = value;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return name + ": " + value;
    }
}
