package com.blurpsuite.core;

import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;

/** Target scope with ordered include and exclude rules. */
public final class Scope {
    private final List<String> includeRules = new ArrayList<>();
    private final List<String> excludeRules = new ArrayList<>();
    private final List<Runnable> changeListeners = new CopyOnWriteArrayList<>();

    public void addChangeListener(Runnable listener) {
        if (listener != null) {
            changeListeners.add(listener);
        }
    }

    public void removeChangeListener(Runnable listener) {
        if (listener != null) {
            changeListeners.remove(listener);
        }
    }

    public synchronized void include(String prefix) {
        if (prefix != null && !prefix.isBlank() && !includeRules.contains(prefix.trim())) {
            includeRules.add(prefix.trim());
            fireChanged();
        }
    }

    public synchronized void exclude(String prefix) {
        if (prefix != null && !prefix.isBlank() && !excludeRules.contains(prefix.trim())) {
            excludeRules.add(prefix.trim());
            fireChanged();
        }
    }

    public synchronized void removeInclude(String prefix) {
        if (prefix != null && includeRules.remove(prefix.trim())) {
            fireChanged();
        }
    }

    public synchronized void removeExclude(String prefix) {
        if (prefix != null && excludeRules.remove(prefix.trim())) {
            fireChanged();
        }
    }

    public synchronized void clear() {
        if (includeRules.isEmpty() && excludeRules.isEmpty()) {
            return;
        }
        includeRules.clear();
        excludeRules.clear();
        fireChanged();
    }

    public synchronized List<String> includes() {
        return Collections.unmodifiableList(new ArrayList<>(includeRules));
    }

    public synchronized List<String> excludes() {
        return Collections.unmodifiableList(new ArrayList<>(excludeRules));
    }

    /** A URL is in scope when at least one include rule matches and no exclude rule matches. */
    public synchronized boolean isInScope(URL url) {
        if (url == null) {
            return false;
        }
        boolean included = includeRules.isEmpty()
                || includeRules.stream().anyMatch(rule -> matches(rule, url));
        boolean excluded = excludeRules.stream().anyMatch(rule -> matches(rule, url));
        return included && !excluded;
    }

    /**
     * Matches a rule against a URL using authority and path boundaries.
     *
     * <p>Rules may be a host, a host with a wildcard subdomain prefix, or a URL
     * with an optional scheme, port and path prefix. Comparing structured parts
     * prevents a rule such as {@code http://example.org} from also matching
     * {@code http://example.org.attacker.test}.</p>
     */
    private static boolean matches(String rule, URL url) {
        String value = rule.trim();
        if (value.isEmpty()) {
            return false;
        }

        boolean wildcardHost = false;
        if (value.startsWith("*.")) {
            wildcardHost = true;
            value = value.substring(2);
        } else if (value.startsWith("*://")) {
            value = value.substring(4);
            if (value.startsWith("*.")) {
                wildcardHost = true;
                value = value.substring(2);
            }
        }

        String ruleScheme = null;
        int schemeEnd = value.indexOf("://");
        if (schemeEnd >= 0) {
            ruleScheme = value.substring(0, schemeEnd).toLowerCase(Locale.ROOT);
            value = value.substring(schemeEnd + 3);
        }

        int pathStart = value.indexOf('/');
        String authority = pathStart >= 0 ? value.substring(0, pathStart) : value;
        String rulePath = pathStart >= 0 ? value.substring(pathStart) : "";
        while (rulePath.length() > 1 && rulePath.endsWith("/")) {
            rulePath = rulePath.substring(0, rulePath.length() - 1);
        }
        if (rulePath.equals("/")) {
            rulePath = "";
        }

        int at = authority.lastIndexOf('@');
        if (at >= 0) {
            authority = authority.substring(at + 1);
        }
        int rulePort = -1;
        String ruleHost;
        if (authority.startsWith("[")) {
            int close = authority.indexOf(']');
            if (close < 0) {
                return false;
            }
            ruleHost = authority.substring(0, close + 1);
            if (close + 1 < authority.length() && authority.charAt(close + 1) == ':') {
                try {
                    rulePort = Integer.parseInt(authority.substring(close + 2));
                } catch (NumberFormatException e) {
                    return false;
                }
            }
        } else {
            int colon = authority.lastIndexOf(':');
            if (colon >= 0 && authority.indexOf(':') == colon) {
                try {
                    rulePort = Integer.parseInt(authority.substring(colon + 1));
                } catch (NumberFormatException e) {
                    return false;
                }
                authority = authority.substring(0, colon);
            }
            ruleHost = authority;
        }
        ruleHost = ruleHost.toLowerCase(Locale.ROOT);
        if (ruleHost.isEmpty()) {
            return false;
        }

        String targetHost = url.getHost() == null ? "" : url.getHost().toLowerCase(Locale.ROOT);
        String targetScheme = url.getProtocol() == null ? "" : url.getProtocol().toLowerCase(Locale.ROOT);
        int targetPort = url.getPort() == -1 ? url.getDefaultPort() : url.getPort();
        if (ruleScheme != null && !ruleScheme.equals(targetScheme)) {
            return false;
        }
        if (rulePort >= 0 && rulePort != targetPort) {
            return false;
        }
        boolean hostMatches = wildcardHost
                ? targetHost.equals(ruleHost) || targetHost.endsWith("." + ruleHost)
                : targetHost.equals(ruleHost);
        if (!hostMatches) {
            return false;
        }
        if (rulePath.isEmpty()) {
            return true;
        }
        String targetPath = url.getPath() == null || url.getPath().isEmpty() ? "/" : url.getPath();
        return targetPath.equals(rulePath) || targetPath.startsWith(rulePath + "/");
    }

    private void fireChanged() {
        for (Runnable listener : changeListeners) {
            try {
                listener.run();
            } catch (RuntimeException ignored) {
                // A broken extension listener must not corrupt the scope.
            }
        }
    }

    @Override
    public synchronized String toString() {
        return "include=" + includeRules + ", exclude=" + excludeRules;
    }
}
