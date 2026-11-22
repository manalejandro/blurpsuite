package com.blurpsuite.core;

import burp.IHttpRequestResponse;
import burp.IHttpRequestResponsePersisted;
import burp.IHttpRequestResponseWithMarkers;
import burp.IHttpService;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** A request/response pair as it travels through the proxy and the extension API. */
public final class HttpExchange implements IHttpRequestResponse, IHttpRequestResponsePersisted,
        IHttpRequestResponseWithMarkers {

    private final long reference;
    private final Instant timestamp;
    private final String listener;
    private final String clientAddress;
    private volatile byte[] request;
    private volatile byte[] response;
    private volatile IHttpService service;
    private volatile String comment;
    private volatile String highlight;
    private volatile List<int[]> requestMarkers = new ArrayList<>();
    private volatile List<int[]> responseMarkers = new ArrayList<>();

    public HttpExchange(long reference, byte[] request, IHttpService service, String listener,
                        String clientAddress) {
        this.reference = reference;
        this.request = request.clone();
        this.service = service;
        this.listener = listener;
        this.clientAddress = clientAddress;
        this.timestamp = Instant.now();
    }

    public long reference() {
        return reference;
    }

    public Instant timestamp() {
        return timestamp;
    }

    public String listener() {
        return listener;
    }

    public String clientAddress() {
        return clientAddress;
    }

    @Override
    public byte[] getRequest() {
        return request.clone();
    }

    @Override
    public void setRequest(byte[] message) {
        this.request = message == null ? new byte[0] : message.clone();
    }

    @Override
    public byte[] getResponse() {
        return response == null ? new byte[0] : response.clone();
    }

    @Override
    public void setResponse(byte[] message) {
        this.response = message == null ? new byte[0] : message.clone();
    }

    @Override
    public IHttpService getHttpService() {
        return service;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.service = httpService;
    }

    @Override
    public String getComment() {
        return comment;
    }

    @Override
    public void setComment(String comment) {
        this.comment = comment;
    }

    @Override
    public String getHighlight() {
        return highlight;
    }

    @Override
    public void setHighlight(String color) {
        this.highlight = color;
    }

    @Override
    public void deleteTempFiles() {
        // Buffers are held in memory only; there is nothing to delete.
    }

    @Override
    public List<int[]> getRequestMarkers() {
        return requestMarkers;
    }

    @Override
    public List<int[]> getResponseMarkers() {
        return responseMarkers;
    }

    public void setMarkers(List<int[]> requestMarkers, List<int[]> responseMarkers) {
        this.requestMarkers = requestMarkers == null ? new ArrayList<>() : new ArrayList<>(requestMarkers);
        this.responseMarkers = responseMarkers == null ? new ArrayList<>() : new ArrayList<>(responseMarkers);
    }
}
