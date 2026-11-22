package com.blurpsuite.api;

import burp.IInterceptedProxyMessage;
import burp.IHttpRequestResponse;

import java.net.InetAddress;
import java.net.UnknownHostException;

/** Mutable proxy message delivered to registered {@link burp.IProxyListener} instances. */
public final class InterceptedProxyMessageImpl implements IInterceptedProxyMessage {
    private final IHttpRequestResponse messageInfo;
    private final int messageReference;
    private final String listenerInterface;
    private final InetAddress clientIpAddress;
    private volatile int interceptAction = ACTION_FOLLOW_RULES;

    public InterceptedProxyMessageImpl(IHttpRequestResponse messageInfo, int messageReference,
                                       String listenerInterface, String clientAddress) {
        this.messageInfo = messageInfo;
        this.messageReference = messageReference;
        this.listenerInterface = listenerInterface == null ? "" : listenerInterface;
        this.clientIpAddress = parseAddress(clientAddress);
    }

    @Override
    public InetAddress getClientIpAddress() {
        return clientIpAddress;
    }

    @Override
    public int getInterceptAction() {
        return interceptAction;
    }

    @Override
    public void setInterceptAction(int interceptAction) {
        this.interceptAction = interceptAction;
    }

    @Override
    public String getListenerInterface() {
        return listenerInterface;
    }

    @Override
    public IHttpRequestResponse getMessageInfo() {
        return messageInfo;
    }

    @Override
    public int getMessageReference() {
        return messageReference;
    }

    private static InetAddress parseAddress(String address) {
        if (address == null || address.isBlank()) {
            return null;
        }
        try {
            return InetAddress.getByName(address);
        } catch (UnknownHostException e) {
            return null;
        }
    }
}
