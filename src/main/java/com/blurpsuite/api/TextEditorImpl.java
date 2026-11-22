package com.blurpsuite.api;

import burp.ITextEditor;
import com.blurpsuite.util.ByteUtil;

import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.Component;
import java.awt.Font;

/** Swing-backed text editor returned by createTextEditor(). */
public final class TextEditorImpl implements ITextEditor {
    private final JTextArea area = new JTextArea();
    private final JScrollPane scrollPane;
    private volatile boolean modified;

    public TextEditorImpl() {
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setLineWrap(false);
        scrollPane = new JScrollPane(area);
    }

    @Override
    public Component getComponent() {
        return scrollPane;
    }

    @Override
    public byte[] getText() {
        return ByteUtil.toBytes(area.getText());
    }

    @Override
    public void setText(byte[] text) {
        area.setText(ByteUtil.toString(text));
        modified = false;
    }

    @Override
    public byte[] getSelectedText() {
        return ByteUtil.toBytes(area.getSelectedText() == null ? "" : area.getSelectedText());
    }

    @Override
    public int[] getSelectionBounds() {
        return new int[]{area.getSelectionStart(), area.getSelectionEnd()};
    }

    @Override
    public boolean isTextModified() {
        return modified || area.getText().length() > 0;
    }

    @Override
    public void setEditable(boolean editable) {
        area.setEditable(editable);
    }

    @Override
    public void setSearchExpression(String expression) {
        String text = area.getText();
        int index = expression == null ? -1 : text.toLowerCase().indexOf(expression.toLowerCase());
        if (index >= 0) {
            area.select(index, index + expression.length());
            area.requestFocus();
        }
    }
}
