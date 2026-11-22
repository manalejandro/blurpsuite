package com.blurpsuite.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small, dependency-free JSON reader/writer used by the Python extension bridge.
 *
 * <p>Only the JSON subset needed by the bridge protocol is supported: objects,
 * arrays, strings, numbers, booleans and null. Numbers are surfaced as {@link Long}
 * for integers and {@link Double} for decimals.</p>
 */
public final class Json {
    private Json() {
    }

    /** Parses one JSON value. Throws {@link IllegalArgumentException} on malformed input. */
    public static Object parse(String text) {
        Parser parser = new Parser(text);
        Object value = parser.readValue();
        parser.skipWhitespace();
        if (!parser.atEnd()) {
            throw parser.error("trailing characters after JSON value");
        }
        return value;
    }

    /** Serializes a value produced by {@link #obj()} or plain Java collections. */
    @SuppressWarnings("unchecked")
    public static String write(Object value) {
        StringBuilder out = new StringBuilder();
        writeValue(out, value);
        return out.toString();
    }

    /** Creates an insertion-ordered JSON object builder. */
    public static Map<String, Object> obj() {
        return new LinkedHashMap<>();
    }

    /** Convenience accessor for string values. */
    public static String string(Object value, String fallback) {
        return value instanceof String s ? s : fallback;
    }

    /** Convenience accessor for numeric values. */
    public static int integer(Object value, int fallback) {
        if (value instanceof Number n) {
            return n.intValue();
        }
        return fallback;
    }

    private static void writeValue(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String s) {
            writeString(out, s);
        } else if (value instanceof Boolean || value instanceof Number) {
            out.append(value);
        } else if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeString(out, String.valueOf(entry.getKey()));
                out.append(':');
                writeValue(out, entry.getValue());
            }
            out.append('}');
        } else if (value instanceof Iterable<?> items) {
            out.append('[');
            boolean first = true;
            for (Object item : items) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeValue(out, item);
            }
            out.append(']');
        } else if (value.getClass().isArray()) {
            out.append('[');
            int length = java.lang.reflect.Array.getLength(value);
            for (int i = 0; i < length; i++) {
                if (i > 0) {
                    out.append(',');
                }
                writeValue(out, java.lang.reflect.Array.get(value, i));
            }
            out.append(']');
        } else {
            writeString(out, String.valueOf(value));
        }
    }

    private static void writeString(StringBuilder out, String value) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    private static final class Parser {
        private final String source;
        private int position;

        Parser(String source) {
            this.source = source;
        }

        boolean atEnd() {
            return position >= source.length();
        }

        void skipWhitespace() {
            while (!atEnd() && Character.isWhitespace(source.charAt(position))) {
                position++;
            }
        }

        Object readValue() {
            skipWhitespace();
            if (atEnd()) {
                throw error("expected a JSON value");
            }
            char c = source.charAt(position);
            return switch (c) {
                case '{' -> readObject();
                case '[' -> readArray();
                case '"' -> readString();
                case 't' -> readLiteral("true", Boolean.TRUE);
                case 'f' -> readLiteral("false", Boolean.FALSE);
                case 'n' -> readLiteral("null", null);
                default -> {
                    if (c == '-' || Character.isDigit(c)) {
                        yield readNumber();
                    }
                    throw error("unexpected character '" + c + "'");
                }
            };
        }

        private Map<String, Object> readObject() {
            position++;
            Map<String, Object> map = new LinkedHashMap<>();
            skipWhitespace();
            if (!atEnd() && source.charAt(position) == '}') {
                position++;
                return map;
            }
            while (true) {
                skipWhitespace();
                if (atEnd() || source.charAt(position) != '"') {
                    throw error("expected object key");
                }
                String key = readString();
                skipWhitespace();
                expect(':');
                map.put(key, readValue());
                skipWhitespace();
                if (atEnd()) {
                    throw error("unterminated object");
                }
                char separator = source.charAt(position++);
                if (separator == '}') {
                    return map;
                }
                if (separator != ',') {
                    throw error("expected ',' or '}'");
                }
            }
        }

        private List<Object> readArray() {
            position++;
            List<Object> list = new ArrayList<>();
            skipWhitespace();
            if (!atEnd() && source.charAt(position) == ']') {
                position++;
                return list;
            }
            while (true) {
                list.add(readValue());
                skipWhitespace();
                if (atEnd()) {
                    throw error("unterminated array");
                }
                char separator = source.charAt(position++);
                if (separator == ']') {
                    return list;
                }
                if (separator != ',') {
                    throw error("expected ',' or ']'");
                }
            }
        }

        private String readString() {
            expect('"');
            StringBuilder value = new StringBuilder();
            while (!atEnd()) {
                char c = source.charAt(position++);
                if (c == '"') {
                    return value.toString();
                }
                if (c != '\\') {
                    value.append(c);
                    continue;
                }
                if (atEnd()) {
                    break;
                }
                char escaped = source.charAt(position++);
                switch (escaped) {
                    case '"', '\\', '/' -> value.append(escaped);
                    case 'b' -> value.append('\b');
                    case 'f' -> value.append('\f');
                    case 'n' -> value.append('\n');
                    case 'r' -> value.append('\r');
                    case 't' -> value.append('\t');
                    case 'u' -> {
                        if (position + 4 > source.length()) {
                            throw error("incomplete unicode escape");
                        }
                        String hex = source.substring(position, position + 4);
                        try {
                            value.append((char) Integer.parseInt(hex, 16));
                        } catch (NumberFormatException e) {
                            throw error("invalid unicode escape");
                        }
                        position += 4;
                    }
                    default -> throw error("invalid escape '\\" + escaped + "'");
                }
            }
            throw error("unterminated string");
        }

        private Object readNumber() {
            int start = position;
            if (source.charAt(position) == '-') {
                position++;
            }
            while (!atEnd() && Character.isDigit(source.charAt(position))) {
                position++;
            }
            boolean decimal = false;
            if (!atEnd() && source.charAt(position) == '.') {
                decimal = true;
                position++;
                while (!atEnd() && Character.isDigit(source.charAt(position))) {
                    position++;
                }
            }
            if (!atEnd() && (source.charAt(position) == 'e' || source.charAt(position) == 'E')) {
                decimal = true;
                position++;
                if (!atEnd() && (source.charAt(position) == '+' || source.charAt(position) == '-')) {
                    position++;
                }
                while (!atEnd() && Character.isDigit(source.charAt(position))) {
                    position++;
                }
            }
            String number = source.substring(start, position);
            try {
                return decimal ? (Object) Double.valueOf(number) : (Object) Long.valueOf(number);
            } catch (NumberFormatException e) {
                throw error("invalid number '" + number + "'");
            }
        }

        private Object readLiteral(String literal, Object value) {
            if (!source.startsWith(literal, position)) {
                throw error("expected '" + literal + "'");
            }
            position += literal.length();
            return value;
        }

        private void expect(char expected) {
            if (atEnd() || source.charAt(position) != expected) {
                throw error("expected '" + expected + "'");
            }
            position++;
        }

        IllegalArgumentException error(String message) {
            return new IllegalArgumentException("JSON at offset " + position + ": " + message);
        }
    }
}
