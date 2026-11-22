"""Python extension that adds a header to every proxied request."""

from burp import IBurpExtender, IProxyListener


class BurpExtender(IBurpExtender, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Python Header Modifier")
        callbacks.registerProxyListener(self)
        callbacks.printOutput("Python Header Modifier loaded")

    def processProxyMessage(self, messageIsRequest, message):
        if not messageIsRequest:
            return
        request = self.helpers.bytesToString(message.getMessageInfo().getRequest())
        if "X-Blurp-Python: yes" not in request:
            lines = request.split("\r\n")
            lines.insert(1, "X-Blurp-Python: yes")
            message.getMessageInfo().setRequest("\r\n".join(lines).encode("latin-1"))
