package com.blurpsuite.ui;

import burp.IResponseInfo;
import com.blurpsuite.core.HttpExchange;
import com.blurpsuite.core.HttpParser;
import com.blurpsuite.core.ProxyServer;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.Timer;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Font;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

/** Read-only HTTP history with request and response viewers. */
public final class HistoryPanel extends JPanel {
    private static final long serialVersionUID = 1L;
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss")
            .withZone(ZoneId.systemDefault());
    private static final String[] COLUMNS = {"#", "Time", "Method", "URL", "Status", "Bytes", "Comment"};

    private final transient ProxyServer proxy;
    private final DefaultTableModel model = new DefaultTableModel(COLUMNS, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private final JTable table = new JTable(model);
    private final JTextArea requestArea = new JTextArea();
    private final JTextArea responseArea = new JTextArea();
    private final transient java.util.List<HttpExchange> displayed = new java.util.ArrayList<>();

    public HistoryPanel(ProxyServer proxy) {
        this.proxy = proxy;
        setLayout(new BorderLayout(0, 0));
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.setRowHeight(22);
        table.getColumnModel().getColumn(0).setMaxWidth(70);
        table.getColumnModel().getColumn(1).setMaxWidth(90);
        table.getColumnModel().getColumn(2).setMaxWidth(80);
        table.getColumnModel().getColumn(4).setMaxWidth(80);
        table.getColumnModel().getColumn(5).setMaxWidth(90);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelected();
            }
        });

        requestArea.setEditable(false);
        responseArea.setEditable(false);
        requestArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        responseArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JTabbedPane viewers = new JTabbedPane();
        viewers.addTab("Request", new JScrollPane(requestArea));
        viewers.addTab("Response", new JScrollPane(responseArea));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), viewers);
        split.setResizeWeight(0.45);
        add(split, BorderLayout.CENTER);

        new Timer(700, e -> refresh()).start();
        refresh();
    }

    private void refresh() {
        List<HttpExchange> items = proxy.recentHistory(1000);
        if (items.size() == displayed.size()) {
            return;
        }
        displayed.clear();
        displayed.addAll(items);
        model.setRowCount(0);
        for (HttpExchange exchange : items) {
            String[] line = HttpParser.startLine(exchange.getRequest());
            String method = line.length > 0 ? line[0] : "-";
            String url = HttpParser.requestUrl(exchange.getRequest(), exchange.getHttpService())
                    .toExternalForm();
            int status = 0;
            if (exchange.getResponse().length > 0) {
                IResponseInfo info = HttpParser.analyzeResponse(exchange.getResponse());
                status = info.getStatusCode();
            }
            model.addRow(new Object[]{
                    exchange.reference(),
                    TIME.format(exchange.timestamp()),
                    method,
                    url,
                    status == 0 ? "-" : status,
                    exchange.getResponse().length,
                    exchange.getComment() == null ? "" : exchange.getComment()
            });
        }
    }

    private void showSelected() {
        int row = table.getSelectedRow();
        if (row < 0 || row >= displayed.size()) {
            return;
        }
        HttpExchange exchange = displayed.get(table.convertRowIndexToModel(row));
        UiSupport.setTextLater(requestArea, UiSupport.messageText(exchange.getRequest()));
        UiSupport.setTextLater(responseArea, UiSupport.messageText(exchange.getResponse()));
    }
}
