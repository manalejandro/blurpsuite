package com.blurpsuite.api;

import burp.IMessageEditor;
import com.blurpsuite.util.ByteUtil;

import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.Component;
import java.awt.Font;

/** Swing-backed message editor returned by createMessageEditor(). */
public final class MessageEditorImpl implements IMessageEditor {
    private final JTextArea area = new JTextArea();
    private final JScrollPane scrollPane;
    private final boolean editable;
    private volatile boolean modified;

    public MessageEditorImpl(boolean editable) {
        this.editable = editable;
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setEditable(editable);
        scrollPane = new JScrollPane(area);
    }

    @Override
    public Component getComponent() {
        return scrollPane;
    }

    @Override
    public byte[] getMessage() {
        return ByteUtil.toBytes(area.getText());
    }

    @Override
    public void setMessage(byte[] message, boolean isRequest) {
        area.setText(ByteUtil.toString(message));
        modified = false;
    }

    @Override
    public byte[] getSelectedData() {
        return ByteUtil.toBytes(area.getSelectedText() == null ? "" : area.getSelectedText());
    }

    @Override
    public int[] getSelectionBounds() {
        return new int[]{area.getSelectionStart(), area.getSelectionEnd()};
    }

    @Override
    public boolean isMessageModified() {
        return modified;
    }
}
