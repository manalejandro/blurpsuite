package examples.java;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;

import java.nio.charset.StandardCharsets;

/** Minimal Java extension that adds a marker header to proxied requests. */
public class HeaderModifier implements IBurpExtender, IProxyListener {
    private IBurpExtenderCallbacks callbacks;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("Java Header Modifier");
        callbacks.registerProxyListener(this);
        callbacks.printOutput("Java Header Modifier loaded");
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (!messageIsRequest) {
            return;
        }
        byte[] request = message.getMessageInfo().getRequest();
        String text = new String(request, StandardCharsets.ISO_8859_1);
        if (text.contains("X-Blurp-Java: yes")) {
            return;
        }
        int lineEnd = text.indexOf("\r\n");
        if (lineEnd < 0) {
            return;
        }
        String modified = text.substring(0, lineEnd + 2)
                + "X-Blurp-Java: yes\r\n" + text.substring(lineEnd + 2);
        message.getMessageInfo().setRequest(modified.getBytes(StandardCharsets.ISO_8859_1));
    }
}
