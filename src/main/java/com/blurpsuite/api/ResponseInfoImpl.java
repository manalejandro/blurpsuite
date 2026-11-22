package com.blurpsuite.api;

import burp.ICookie;
import burp.IResponseInfo;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Parsed view of an HTTP response. */
public final class ResponseInfoImpl implements IResponseInfo {
    private final short statusCode;
    private final List<String> headers;
    private final List<ICookie> cookies;
    private final int bodyOffset;
    private final String statedMimeType;
    private final String inferredMimeType;

    public ResponseInfoImpl(short statusCode, List<String> headers, List<ICookie> cookies, int bodyOffset,
                            String statedMimeType, String inferredMimeType) {
        this.statusCode = statusCode;
        this.headers = new ArrayList<>(headers);
        this.cookies = new ArrayList<>(cookies);
        this.bodyOffset = bodyOffset;
        this.statedMimeType = statedMimeType;
        this.inferredMimeType = inferredMimeType;
    }

    @Override
    public short getStatusCode() {
        return statusCode;
    }

    @Override
    public List<String> getHeaders() {
        return Collections.unmodifiableList(headers);
    }

    @Override
    public List<ICookie> getCookies() {
        return Collections.unmodifiableList(cookies);
    }

    @Override
    public int getBodyOffset() {
        return bodyOffset;
    }

    @Override
    public String getStatedMimeType() {
        return statedMimeType;
    }

    @Override
    public String getInferredMimeType() {
        return inferredMimeType;
    }
}
