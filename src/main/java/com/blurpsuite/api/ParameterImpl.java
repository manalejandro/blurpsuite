package com.blurpsuite.api;

import burp.IParameter;

/** Value object implementing the Extender API parameter contract. */
public final class ParameterImpl implements IParameter {
    private final String name;
    private final String value;
    private final byte type;
    private final int nameStart;
    private final int nameEnd;
    private final int valueStart;
    private final int valueEnd;

    public ParameterImpl(String name, String value, byte type, int nameStart, int nameEnd,
                         int valueStart, int valueEnd) {
        this.name = name;
        this.value = value;
        this.type = type;
        this.nameStart = nameStart;
        this.nameEnd = nameEnd;
        this.valueStart = valueStart;
        this.valueEnd = valueEnd;
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
    public byte getType() {
        return type;
    }

    @Override
    public int getNameStart() {
        return nameStart;
    }

    @Override
    public int getNameEnd() {
        return nameEnd;
    }

    @Override
    public int getValueStart() {
        return valueStart;
    }

    @Override
    public int getValueEnd() {
        return valueEnd;
    }

    @Override
    public String toString() {
        return name + "=" + value + " (type " + type + ")";
    }
}
