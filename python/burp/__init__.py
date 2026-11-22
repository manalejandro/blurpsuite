"""Python-compatible Burp Extender API for Blurp Suite.

This package mirrors the names of PortSwigger's Extender interfaces so that
extensions written in the familiar Jython style can be loaded by Blurp Suite's
Python bridge.  The interfaces are plain classes with no-op methods: an
extension only needs to override the callbacks it is interested in.
"""

from .api import (
    ACTION_DONT_INTERCEPT,
    ACTION_DONT_INTERCEPT_AND_REHOOK,
    ACTION_DO_INTERCEPT,
    ACTION_DO_INTERCEPT_AND_REHOOK,
    ACTION_DROP,
    ACTION_FOLLOW_RULES,
    ACTION_FOLLOW_RULES_AND_REHOOK,
    TOOL_COMPARER,
    TOOL_DECODER,
    TOOL_EXTENDER,
    TOOL_INTRUDER,
    TOOL_PROXY,
    TOOL_REPEATER,
    TOOL_SCANNER,
    TOOL_SEQUENCER,
    TOOL_SPIDER,
    TOOL_SUITE,
    TOOL_TARGET,
    BurpExtenderCallbacks,
    Cookie,
    Helpers,
    HttpHeader,
    HttpService,
    HttpRequestResponse,
    InterceptedProxyMessage,
    Parameter,
    RequestInfo,
    ResponseInfo,
)

__all__ = [
    "IBurpExtender",
    "IBurpExtenderCallbacks",
    "IExtensionHelpers",
    "IExtensionStateListener",
    "IProxyListener",
    "IHttpListener",
    "IHttpService",
    "IHttpRequestResponse",
    "IHttpRequestResponsePersisted",
    "IHttpRequestResponseWithMarkers",
    "IInterceptedProxyMessage",
    "IRequestInfo",
    "IResponseInfo",
    "IResponseKeywords",
    "IResponseVariations",
    "IMenuItemHandler",
    "IParameter",
    "IHttpHeader",
    "ICookie",
    "IContextMenuFactory",
    "IContextMenuInvocation",
    "IMessageEditor",
    "IMessageEditorController",
    "IMessageEditorTab",
    "IMessageEditorTabFactory",
    "ITextEditor",
    "ITab",
    "IScanIssue",
    "IScanQueueItem",
    "IScannerCheck",
    "IScannerListener",
    "IScannerInsertionPoint",
    "IScannerInsertionPointProvider",
    "ISessionHandlingAction",
    "IIntruderAttack",
    "IIntruderPayloadGenerator",
    "IIntruderPayloadGeneratorFactory",
    "IIntruderPayloadProcessor",
    "IBurpCollaboratorClientContext",
    "IBurpCollaboratorInteraction",
    "ITempFile",
    "IScopeChangeListener",
    "ACTION_FOLLOW_RULES",
    "ACTION_DO_INTERCEPT",
    "ACTION_DONT_INTERCEPT",
    "ACTION_DROP",
    "ACTION_FOLLOW_RULES_AND_REHOOK",
    "ACTION_DO_INTERCEPT_AND_REHOOK",
    "ACTION_DONT_INTERCEPT_AND_REHOOK",
    "TOOL_SUITE",
    "TOOL_TARGET",
    "TOOL_PROXY",
    "TOOL_SPIDER",
    "TOOL_SCANNER",
    "TOOL_INTRUDER",
    "TOOL_REPEATER",
    "TOOL_SEQUENCER",
    "TOOL_DECODER",
    "TOOL_COMPARER",
    "TOOL_EXTENDER",
    "BurpExtenderCallbacks",
    "Helpers",
    "HttpRequestResponse",
    "InterceptedProxyMessage",
    "RequestInfo",
    "ResponseInfo",
    "Parameter",
    "HttpHeader",
    "Cookie",
    "HttpService",
]


class _Interface:
    """Base class whose methods can be overridden selectively."""

    def __init__(self, *args, **kwargs):
        pass


class IBurpExtender(_Interface):
    def registerExtenderCallbacks(self, callbacks):
        """Called once after the extension has been loaded."""


class IBurpExtenderCallbacks(_Interface):
    TOOL_SUITE = 1
    TOOL_TARGET = 2
    TOOL_PROXY = 4
    TOOL_SPIDER = 8
    TOOL_SCANNER = 16
    TOOL_INTRUDER = 32
    TOOL_REPEATER = 64
    TOOL_SEQUENCER = 128
    TOOL_DECODER = 256
    TOOL_COMPARER = 512
    TOOL_EXTENDER = 1024

    def setExtensionName(self, name):
        pass

    def getExtensionFilename(self):
        return ""

    def getBurpVersion(self):
        return ("Blurp Suite", "1.0.0", "community")

    def getHelpers(self):
        return None

    def printOutput(self, message):
        pass

    def printError(self, message):
        pass

    def registerProxyListener(self, listener):
        pass

    def registerHttpListener(self, listener):
        pass

    def registerExtensionStateListener(self, listener):
        pass

    def isInScope(self, url):
        return False

    def saveExtensionSetting(self, name, value):
        pass

    def loadExtensionSetting(self, name):
        return None

    def getProxyHistory(self):
        return []


def _callback_stub(name):
    def stub(self, *args, **kwargs):
        return None

    stub.__name__ = name
    stub.__qualname__ = "IBurpExtenderCallbacks." + name
    stub.__doc__ = "Compatibility stub for " + name + "."
    return stub


# Mirror the concrete callback surface so Jython-style code can inspect or
# subclass the published interface without losing any method names.
for _callback_name in dir(BurpExtenderCallbacks):
    if (_callback_name.startswith("_")
            or not callable(getattr(BurpExtenderCallbacks, _callback_name))
            or hasattr(IBurpExtenderCallbacks, _callback_name)):
        continue
    setattr(IBurpExtenderCallbacks, _callback_name, _callback_stub(_callback_name))


class IExtensionHelpers(_Interface):
    pass


class IExtensionStateListener(_Interface):
    def extensionUnloaded(self):
        pass


class IProxyListener(_Interface):
    def processProxyMessage(self, messageIsRequest, message):
        pass


class IHttpListener(_Interface):
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass


class IHttpService(_Interface):
    def getHost(self):
        return ""

    def getPort(self):
        return 0

    def getProtocol(self):
        return "http"


class IHttpRequestResponse(_Interface):
    def getRequest(self):
        return b""

    def setRequest(self, message):
        pass

    def getResponse(self):
        return b""

    def setResponse(self, message):
        pass

    def getHttpService(self):
        return None

    def setHttpService(self, service):
        pass

    def getComment(self):
        return None

    def setComment(self, comment):
        pass

    def getHighlight(self):
        return None

    def setHighlight(self, color):
        pass


class IHttpRequestResponsePersisted(IHttpRequestResponse):
    def deleteTempFiles(self):
        pass


class IHttpRequestResponseWithMarkers(IHttpRequestResponse):
    def getRequestMarkers(self):
        return []

    def getResponseMarkers(self):
        return []


class IInterceptedProxyMessage(_Interface):
    ACTION_FOLLOW_RULES = 0
    ACTION_DO_INTERCEPT = 1
    ACTION_DONT_INTERCEPT = 2
    ACTION_DROP = 3
    ACTION_FOLLOW_RULES_AND_REHOOK = 16
    ACTION_DO_INTERCEPT_AND_REHOOK = 17
    ACTION_DONT_INTERCEPT_AND_REHOOK = 18

    def getClientIpAddress(self):
        return None

    def getInterceptAction(self):
        return 0

    def setInterceptAction(self, action):
        pass

    def getListenerInterface(self):
        return ""

    def getMessageInfo(self):
        return None

    def getMessageReference(self):
        return 0


class IRequestInfo(_Interface):
    CONTENT_TYPE_NONE = 0
    CONTENT_TYPE_URL_ENCODED = 1
    CONTENT_TYPE_MULTIPART = 2
    CONTENT_TYPE_XML = 3
    CONTENT_TYPE_JSON = 4
    CONTENT_TYPE_AMF = 5
    CONTENT_TYPE_UNKNOWN = -1

    def getMethod(self):
        return ""

    def getUrl(self):
        return None

    def getHeaders(self):
        return []

    def getParameters(self):
        return []

    def getBodyOffset(self):
        return 0

    def getContentType(self):
        return 0


class IResponseInfo(_Interface):
    def getStatusCode(self):
        return 0

    def getHeaders(self):
        return []

    def getCookies(self):
        return []

    def getBodyOffset(self):
        return 0

    def getStatedMimeType(self):
        return ""

    def getInferredMimeType(self):
        return ""


class IResponseKeywords(_Interface):
    def getInvariantKeywords(self):
        return []

    def getKeywordCount(self, keyword, responseIndex):
        return 0

    def getVariantKeywords(self):
        return []

    def updateWith(self, *responses):
        pass


class IResponseVariations(_Interface):
    def getAttributeValue(self, attributeName, responseIndex):
        return 0

    def getInvariantAttributes(self):
        return []

    def getVariantAttributes(self):
        return []

    def updateWith(self, *responses):
        pass


class IMenuItemHandler(_Interface):
    def menuItemClicked(self, menuItemCaption, messageInfo):
        pass


class IParameter(_Interface):
    PARAM_URL = 0
    PARAM_BODY = 1
    PARAM_COOKIE = 2
    PARAM_XML = 3
    PARAM_XML_ATTR = 4
    PARAM_MULTIPART_ATTR = 5
    PARAM_JSON = 6

    def getName(self):
        return ""

    def getValue(self):
        return ""

    def getType(self):
        return 0

    def getNameStart(self):
        return -1

    def getNameEnd(self):
        return -1

    def getValueStart(self):
        return -1

    def getValueEnd(self):
        return -1


class IHttpHeader(_Interface):
    def getName(self):
        return ""

    def getValue(self):
        return ""


class ICookie(_Interface):
    def getDomain(self):
        return ""

    def getExpiration(self):
        return None

    def getName(self):
        return ""

    def getPath(self):
        return ""

    def getValue(self):
        return ""


class IContextMenuFactory(_Interface):
    def createMenuItems(self, invocation):
        return []


class IContextMenuInvocation(_Interface):
    CONTEXT_MESSAGE_EDITOR_REQUEST = 0
    CONTEXT_MESSAGE_EDITOR_RESPONSE = 1
    CONTEXT_MESSAGE_VIEWER_REQUEST = 2
    CONTEXT_MESSAGE_VIEWER_RESPONSE = 3
    CONTEXT_TARGET_SITE_MAP_TREE = 4
    CONTEXT_TARGET_SITE_MAP_TABLE = 5
    CONTEXT_PROXY_HISTORY = 6
    CONTEXT_SCANNER_RESULTS = 7
    CONTEXT_INTRUDER_PAYLOAD_POSITIONS = 8
    CONTEXT_INTRUDER_ATTACK_RESULTS = 9
    CONTEXT_SEARCH_RESULTS = 10


class IMessageEditor(_Interface):
    def getComponent(self):
        return None

    def getMessage(self):
        return b""

    def setMessage(self, message, isRequest):
        pass

    def getSelectedData(self):
        return b""

    def getSelectionBounds(self):
        return (0, 0)

    def isMessageModified(self):
        return False


class IMessageEditorController(_Interface):
    def getHttpService(self):
        return None

    def getRequest(self):
        return b""

    def getResponse(self):
        return b""


class IMessageEditorTab(_Interface):
    def getTabCaption(self):
        return ""

    def getUiComponent(self):
        return None

    def isEnabled(self, content, isRequest):
        return False

    def setMessage(self, content, isRequest):
        pass

    def getMessage(self):
        return b""

    def isModified(self):
        return False

    def getSelectedData(self):
        return b""


class IMessageEditorTabFactory(_Interface):
    def createNewInstance(self, controller):
        return None


class ITextEditor(_Interface):
    def getComponent(self):
        return None

    def getText(self):
        return b""

    def setText(self, text):
        pass

    def getSelectedText(self):
        return b""

    def getSelectionBounds(self):
        return (0, 0)

    def isTextModified(self):
        return False

    def setEditable(self, editable):
        pass

    def setSearchExpression(self, expression):
        pass


class ITab(_Interface):
    def getTabCaption(self):
        return ""

    def getUiComponent(self):
        return None


class IScanIssue(_Interface):
    def getUrl(self):
        return None

    def getHttpMessages(self):
        return []

    def getHttpService(self):
        return None

    def getIssueName(self):
        return ""

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return ""

    def getConfidence(self):
        return ""

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return None

    def getRemediationDetail(self):
        return None


class IScanQueueItem(_Interface):
    def cancel(self):
        pass

    def getIssues(self):
        return []

    def getNumErrors(self):
        return 0

    def getNumInsertionPoints(self):
        return 0

    def getNumRequests(self):
        return 0

    def getPercentageComplete(self):
        return 0

    def getStatus(self):
        return ""


class IScannerCheck(_Interface):
    def doPassiveScan(self, baseRequestResponse):
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return 0


class IScannerListener(_Interface):
    def newScanIssue(self, issue):
        pass


class IScannerInsertionPoint(_Interface):
    INS_PARAM_URL = 0
    INS_PARAM_BODY = 1
    INS_PARAM_COOKIE = 2
    INS_PARAM_XML = 3
    INS_PARAM_XML_ATTR = 4
    INS_PARAM_MULTIPART_ATTR = 5
    INS_PARAM_JSON = 6
    INS_PARAM_AMF = 7
    INS_URL_PATH_FILENAME = 37
    INS_URL_PATH_FOLDER = 33
    INS_URL_PATH_REST = 33
    INS_HEADER = 32
    INS_PARAM_NAME_URL = 34
    INS_PARAM_NAME_BODY = 35
    INS_ENTIRE_BODY = 36
    INS_USER_PROVIDED = 64
    INS_EXTENSION_PROVIDED = 65
    INS_UNKNOWN = 127

    def getBaseValue(self):
        return ""

    def buildRequest(self, payload):
        return b""

    def getPayloadOffsets(self, payload):
        return (0, 0)

    def getInsertionPointName(self):
        return ""

    def getInsertionPointType(self):
        return 0


class IScannerInsertionPointProvider(_Interface):
    def createInsertionPoints(self, baseRequestResponse):
        return []


class ISessionHandlingAction(_Interface):
    def getActionName(self):
        return ""

    def performAction(self, currentRequest, macroItems):
        pass


class IIntruderAttack(_Interface):
    def getHttpService(self):
        return None

    def getRequestTemplate(self):
        return b""


class IIntruderPayloadGenerator(_Interface):
    def getNextPayload(self, baseValue):
        return b""

    def hasMorePayloads(self):
        return False

    def reset(self):
        pass


class IIntruderPayloadGeneratorFactory(_Interface):
    def createNewInstance(self, attack):
        return None

    def getGeneratorName(self):
        return ""


class IIntruderPayloadProcessor(_Interface):
    def getProcessorName(self):
        return ""

    def processPayload(self, currentPayload, originalPayload, baseValue):
        return b""


class IBurpCollaboratorClientContext(_Interface):
    def generatePayload(self, includeCollaboratorServerLocation):
        return ""

    def getCollaboratorServerLocation(self):
        return ""

    def fetchAllCollaboratorInteractions(self):
        return []

    def fetchAllInfiltratorInteractions(self):
        return []

    def fetchCollaboratorInteractionsFor(self, payload):
        return []

    def fetchInfiltratorInteractionsFor(self, payload):
        return []


class IBurpCollaboratorInteraction(_Interface):
    def getProperties(self):
        return {}

    def getProperty(self, name):
        return None


class ITempFile(_Interface):
    def getBuffer(self):
        return b""

    def delete(self):
        pass


class IScopeChangeListener(_Interface):
    def scopeChanged(self):
        pass
