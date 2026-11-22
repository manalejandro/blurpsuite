package com.blurpsuite.ui;

import burp.ITab;

/** Contract used by extension panels to contribute suite tabs. */
public interface TabHost {
    void addExtensionTab(ITab tab);
}
