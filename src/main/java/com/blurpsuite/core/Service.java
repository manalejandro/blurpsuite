package com.blurpsuite.core;

import burp.IHttpService;

/** Immutable description of an upstream HTTP service. */
public final class Service implements IHttpService {
    private final String host;
    private final int port;
    private final String protocol;

    public Service(String host, int port, String protocol) {
        this.host = host;
        this.port = port;
        this.protocol = "https".equalsIgnoreCase(protocol) ? "https" : "http";
    }

    @Override
    public String getHost() {
        return host;
    }

    @Override
    public int getPort() {
        return port;
    }

    @Override
    public String getProtocol() {
        return protocol;
    }

    public boolean isSecure() {
        return "https".equals(protocol);
    }

    @Override
    public String toString() {
        return protocol + "://" + host + ":" + port;
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof Service service)) {
            return false;
        }
        return port == service.port && host.equalsIgnoreCase(service.host)
                && protocol.equals(service.protocol);
    }

    @Override
    public int hashCode() {
        return (host.toLowerCase() + "|" + port + "|" + protocol).hashCode();
    }
}
