import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

/** Test fixture: records how many times the host calls extensionUnloaded(). */
public class StateListenerExtension implements IBurpExtender, IExtensionStateListener {
    private final AtomicInteger calls = new AtomicInteger();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("State Listener Test (Java)");
        callbacks.registerExtensionStateListener(this);
    }

    @Override
    public void extensionUnloaded() {
        String marker = System.getenv("BLURP_TEST_MARKER");
        if (marker == null || marker.isBlank()) {
            return;
        }
        try {
            Files.writeString(Path.of(marker + ".java"), calls.incrementAndGet() + "\n");
        } catch (Exception ignored) {
            // Best effort: the test asserts the marker is absent on failure.
        }
    }
}
