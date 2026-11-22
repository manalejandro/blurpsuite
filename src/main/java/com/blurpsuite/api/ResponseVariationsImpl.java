package com.blurpsuite.api;

import burp.IResponseVariations;
import com.blurpsuite.core.HttpParser;
import com.blurpsuite.util.ByteUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Tracks simple, comparable attributes across a set of responses. */
public final class ResponseVariationsImpl implements IResponseVariations {
    private static final String[] ATTRIBUTES = {"status_code", "content_length", "header_count",
            "body_offset", "etag", "location"};

    private final List<Map<String, Integer>> rows = new ArrayList<>();

    public ResponseVariationsImpl(byte[][] responses) {
        updateWith(responses);
    }

    @Override
    public int getAttributeValue(String attributeName, int responseIndex) {
        if (responseIndex < 0 || responseIndex >= rows.size()) {
            return 0;
        }
        return rows.get(responseIndex).getOrDefault(attributeName, 0);
    }

    @Override
    public List<String> getVariantAttributes() {
        List<String> result = new ArrayList<>();
        for (String attribute : ATTRIBUTES) {
            Integer first = rows.isEmpty() ? 0 : rows.get(0).getOrDefault(attribute, 0);
            boolean varies = rows.stream().anyMatch(row -> row.getOrDefault(attribute, 0) != first);
            if (varies) {
                result.add(attribute);
            }
        }
        return Collections.unmodifiableList(result);
    }

    @Override
    public List<String> getInvariantAttributes() {
        List<String> result = new ArrayList<>();
        Collections.addAll(result, ATTRIBUTES);
        result.removeAll(getVariantAttributes());
        return Collections.unmodifiableList(result);
    }

    @Override
    public void updateWith(byte[]... responses) {
        rows.clear();
        for (byte[] response : responses) {
            Map<String, Integer> row = new LinkedHashMap<>();
            String[] line = HttpParser.startLine(response);
            row.put("status_code", parseStatus(line.length > 1 ? line[1] : "0"));
            row.put("content_length", response.length);
            row.put("header_count", HttpParser.headerLines(response).size());
            row.put("body_offset", HttpParser.bodyOffset(response));
            row.put("etag", headerPresent(response, "ETag"));
            row.put("location", headerPresent(response, "Location"));
            rows.add(row);
        }
    }

    private static int headerPresent(byte[] response, String name) {
        return HttpParser.header(response, name) == null ? 0 : 1;
    }

    private static int parseStatus(String value) {
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
