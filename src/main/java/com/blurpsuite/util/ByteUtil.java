package com.blurpsuite.util;

import java.nio.charset.StandardCharsets;

/** Byte-level helpers used by the HTTP parser and the compatibility helpers. */
public final class ByteUtil {
    private ByteUtil() {
    }

    public static byte[] toBytes(String text) {
        return text.getBytes(StandardCharsets.ISO_8859_1);
    }

    public static String toString(byte[] data) {
        return data == null ? "" : new String(data, StandardCharsets.ISO_8859_1);
    }

    public static String utf8(byte[] data) {
        return data == null ? "" : new String(data, StandardCharsets.UTF_8);
    }

    public static int indexOf(byte[] data, byte[] pattern, boolean caseSensitive, int from, int to) {
        if (data == null || pattern == null || pattern.length == 0 || from < 0 || to > data.length || from > to) {
            return -1;
        }
        int end = to - pattern.length;
        for (int i = from; i <= end; i++) {
            boolean match = true;
            for (int j = 0; j < pattern.length; j++) {
                byte a = data[i + j];
                byte b = pattern[j];
                if (!caseSensitive) {
                    a = (byte) Character.toUpperCase(a & 0xFF);
                    b = (byte) Character.toUpperCase(b & 0xFF);
                }
                if (a != b) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i;
            }
        }
        return -1;
    }

    public static byte[] concat(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    public static byte[] copyOfRange(byte[] data, int from, int to) {
        int start = Math.max(0, Math.min(from, data.length));
        int end = Math.max(start, Math.min(to, data.length));
        byte[] result = new byte[end - start];
        System.arraycopy(data, start, result, 0, result.length);
        return result;
    }
}
