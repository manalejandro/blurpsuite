package com.blurpsuite.api;

import burp.IHttpListener;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import com.blurpsuite.core.HttpExchange;
import com.blurpsuite.core.TrafficListener;

/** Bridges proxy traffic into the listener callbacks registered by extensions. */
public final class ApiTrafficBridge implements TrafficListener {
    private static final int MAX_REHOOK_PASSES = 8;

    private final BurpExtenderCallbacksImpl callbacks;

    public ApiTrafficBridge(BurpExtenderCallbacksImpl callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public boolean onMessage(boolean messageIsRequest, HttpExchange exchange) {
        int reference = (int) (exchange.reference() & 0x7FFFFFFF);
        InterceptedProxyMessageImpl proxyMessage = new InterceptedProxyMessageImpl(
                exchange, reference, exchange.listener(), exchange.clientAddress());
        int action = IInterceptedProxyMessage.ACTION_FOLLOW_RULES;

        for (int pass = 0; pass <= MAX_REHOOK_PASSES; pass++) {
            proxyMessage.setInterceptAction(IInterceptedProxyMessage.ACTION_FOLLOW_RULES);
            for (IProxyListener listener : callbacks.proxyListeners()) {
                try {
                    listener.processProxyMessage(messageIsRequest, proxyMessage);
                } catch (RuntimeException e) {
                    callbacks.printError("proxy listener failed: " + e);
                }
            }
            action = proxyMessage.getInterceptAction();
            if (!isRehookAction(action) || pass == MAX_REHOOK_PASSES) {
                break;
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
        return action != IInterceptedProxyMessage.ACTION_DROP;
    }

    private static boolean isRehookAction(int action) {
        return action == IInterceptedProxyMessage.ACTION_FOLLOW_RULES_AND_REHOOK
                || action == IInterceptedProxyMessage.ACTION_DO_INTERCEPT_AND_REHOOK
                || action == IInterceptedProxyMessage.ACTION_DONT_INTERCEPT_AND_REHOOK;
    }
}
