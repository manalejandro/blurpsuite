package com.blurpsuite.api;

import burp.IHttpListener;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import com.blurpsuite.core.HttpExchange;
import com.blurpsuite.core.TrafficListener;

/** Bridges proxy traffic into the listener callbacks registered by extensions. */
public final class ApiTrafficBridge implements TrafficListener {
    private final BurpExtenderCallbacksImpl callbacks;

    public ApiTrafficBridge(BurpExtenderCallbacksImpl callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public boolean onMessage(boolean messageIsRequest, HttpExchange exchange) {
        int reference = (int) (exchange.reference() & 0x7FFFFFFF);
        InterceptedProxyMessageImpl proxyMessage = new InterceptedProxyMessageImpl(
                exchange, reference, exchange.listener(), exchange.clientAddress());

        for (IProxyListener listener : callbacks.proxyListeners()) {
            try {
                listener.processProxyMessage(messageIsRequest, proxyMessage);
            } catch (RuntimeException e) {
                callbacks.printError("proxy listener failed: " + e);
            }
        }
        for (IHttpListener listener : callbacks.httpListeners()) {
            try {
                listener.processHttpMessage(burp.IBurpExtenderCallbacks.TOOL_PROXY,
                        messageIsRequest, exchange);
            } catch (RuntimeException e) {
                callbacks.printError("http listener failed: " + e);
            }
        }
        return proxyMessage.getInterceptAction() != IInterceptedProxyMessage.ACTION_DROP;
    }
}
