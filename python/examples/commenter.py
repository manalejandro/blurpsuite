"""Python extension that labels response traffic passing through the proxy."""

from burp import IBurpExtender, IProxyListener


class BurpExtender(IBurpExtender, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        callbacks.setExtensionName("Python Traffic Commenter")
        callbacks.registerProxyListener(self)

    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest:
            return
        info = message.getMessageInfo()
        service = info.getHttpService()
        info.setComment("Python saw %s://%s:%d" %
                        (service.getProtocol(), service.getHost(), service.getPort()))
        info.setHighlight("yellow")
