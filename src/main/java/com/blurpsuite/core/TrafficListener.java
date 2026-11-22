package com.blurpsuite.core;

/** Internal hook for components (extensions, UI, logger) that observe proxy traffic. */
public interface TrafficListener {
    /**
     * Called for each request before it is sent upstream and each response before it is
     * returned to the client.
     *
     * @param messageIsRequest true for requests, false for responses
     * @param exchange         the mutable message being processed
     * @return true to continue forwarding, false to drop the message
     */
    boolean onMessage(boolean messageIsRequest, HttpExchange exchange);
}
