package com.blurpsuite.api;

import burp.IScannerInsertionPoint;
import com.blurpsuite.util.ByteUtil;

/** A byte-range insertion point over a base request. */
public final class ScannerInsertionPointImpl implements IScannerInsertionPoint {
    private final String name;
    private final byte[] baseRequest;
    private final int from;
    private final int to;
    private final byte type;

    public ScannerInsertionPointImpl(String name, byte[] baseRequest, int from, int to, byte type) {
        this.name = name;
        this.baseRequest = baseRequest.clone();
        this.from = Math.max(0, Math.min(from, baseRequest.length));
        this.to = Math.max(this.from, Math.min(to, baseRequest.length));
        this.type = type;
    }

    @Override
    public byte[] buildRequest(byte[] payload) {
        return ByteUtil.concat(ByteUtil.concat(ByteUtil.copyOfRange(baseRequest, 0, from), payload),
                ByteUtil.copyOfRange(baseRequest, to, baseRequest.length));
    }

    @Override
    public int[] getPayloadOffsets(byte[] payload) {
        return new int[]{from, from + payload.length};
    }

    @Override
    public String getBaseValue() {
        return ByteUtil.toString(ByteUtil.copyOfRange(baseRequest, from, to));
    }

    @Override
    public String getInsertionPointName() {
        return name;
    }

    @Override
    public byte getInsertionPointType() {
        return type;
    }
}
