package com.blurpsuite.ui;

import com.blurpsuite.util.ByteUtil;

import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/** Small Swing helpers shared by the UI panels. */
public final class UiSupport {
    private UiSupport() {
    }

    /** Output stream that mirrors extension output into a text component. */
    public static final class ConsoleStream extends OutputStream {
        private final JTextArea area;
        private final OutputStream delegate;
        private final StringBuilder buffer = new StringBuilder();

        public ConsoleStream(JTextArea area, OutputStream delegate) {
            this.area = area;
            this.delegate = delegate;
        }

        @Override
        public void write(int value) {
            write(new byte[]{(byte) value}, 0, 1);
        }

        @Override
        public void write(byte[] data, int offset, int length) {
            String text = new String(data, offset, length, StandardCharsets.UTF_8);
            if (delegate != null) {
                try {
                    delegate.write(data, offset, length);
                    delegate.flush();
                } catch (Exception ignored) {
                    // The mirror is best effort.
                }
            }
            synchronized (buffer) {
                buffer.append(text);
                while (buffer.indexOf("\n") >= 0) {
                    int end = buffer.indexOf("\n");
                    String line = buffer.substring(0, end).replace("\r", "");
                    buffer.delete(0, end + 1);
                    SwingUtilities.invokeLater(() -> appendLine(area, line));
                }
            }
        }

        private static void appendLine(JTextArea area, String line) {
            if (area.getDocument().getLength() > 200_000) {
                area.setText("");
            }
            area.append(line + "\n");
            area.setCaretPosition(area.getDocument().getLength());
        }
    }

    public static String messageText(byte[] data) {
        return ByteUtil.toString(data == null ? new byte[0] : data);
    }

    public static void setTextLater(JTextArea area, String text) {
        SwingUtilities.invokeLater(() -> {
            area.setText(text);
            area.setCaretPosition(0);
        });
    }
}
