package com.blurpsuite.api;

import burp.IResponseKeywords;
import com.blurpsuite.util.ByteUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Counts a fixed set of keywords across a set of responses. */
public final class ResponseKeywordsImpl implements IResponseKeywords {
    private final List<String> keywords;
    private final List<int[]> counts = new ArrayList<>();

    public ResponseKeywordsImpl(List<String> keywords, byte[][] responses) {
        this.keywords = new ArrayList<>(keywords);
        updateWith(responses);
    }

    @Override
    public int getKeywordCount(String keyword, int responseIndex) {
        if (responseIndex < 0 || responseIndex >= counts.size()) {
            return 0;
        }
        int index = keywords.indexOf(keyword);
        return index < 0 ? 0 : counts.get(responseIndex)[index];
    }

    @Override
    public List<String> getVariantKeywords() {
        List<String> result = new ArrayList<>();
        for (int i = 0; i < keywords.size(); i++) {
            final int index = i;
            int first = counts.isEmpty() ? 0 : counts.get(0)[index];
            boolean varies = counts.stream().anyMatch(row -> row[index] != first);
            if (varies) {
                result.add(keywords.get(index));
            }
        }
        return Collections.unmodifiableList(result);
    }

    @Override
    public List<String> getInvariantKeywords() {
        List<String> result = new ArrayList<>(keywords);
        result.removeAll(getVariantKeywords());
        return Collections.unmodifiableList(result);
    }

    @Override
    public void updateWith(byte[]... responses) {
        counts.clear();
        for (byte[] response : responses) {
            String text = ByteUtil.toString(response);
            int[] row = new int[keywords.size()];
            for (int i = 0; i < keywords.size(); i++) {
                String keyword = keywords.get(i);
                if (keyword == null || keyword.isEmpty()) {
                    continue;
                }
                int index = 0;
                while ((index = text.indexOf(keyword, index)) >= 0) {
                    row[i]++;
                    index += keyword.length();
                }
            }
            counts.add(row);
        }
    }
}
