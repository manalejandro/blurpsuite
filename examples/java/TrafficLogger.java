package examples.java;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;

/** Java extension that prints one line per proxied request and response. */
public class TrafficLogger implements IBurpExtender, IProxyListener {
    private IBurpExtenderCallbacks callbacks;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("Java Traffic Logger");
        callbacks.registerProxyListener(this);
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        IHttpRequestResponse info = message.getMessageInfo();
        StringBuilder line = new StringBuilder();
        line.append(messageIsRequest ? "REQUEST " : "RESPONSE ");
        if (info.getHttpService() != null) {
            line.append(info.getHttpService().getProtocol()).append("://")
                    .append(info.getHttpService().getHost()).append(':')
                    .append(info.getHttpService().getPort()).append(' ');
        }
        line.append('(').append(messageIsRequest
                ? info.getRequest().length : info.getResponse().length).append(" bytes)");
        callbacks.printOutput(line.toString());
    }
}
