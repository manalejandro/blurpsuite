package com.blurpsuite.api;

import burp.ICookie;

import java.util.Date;

/** Cookie value object used by the response analyzer and cookie jar. */
public final class CookieImpl implements ICookie {
    private final String domain;
    private final Date expiration;
    private final String name;
    private final String path;
    private final String value;

    public CookieImpl(String domain, Date expiration, String name, String path, String value) {
        this.domain = domain;
        this.expiration = expiration;
        this.name = name;
        this.path = path;
        this.value = value;
    }

    @Override
    public String getDomain() {
        return domain;
    }

    @Override
    public Date getExpiration() {
        return expiration == null ? null : new Date(expiration.getTime());
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getPath() {
        return path;
    }

    @Override
    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return name + "=" + value;
    }
}
