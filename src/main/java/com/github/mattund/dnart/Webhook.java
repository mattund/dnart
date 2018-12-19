package com.github.mattund.dnart;

public class Webhook {
    private final String title, url;

    Webhook(String title, String url) {
        this.title = title;
        this.url = url;
    }

    public String getTitle() {
        return title;
    }

    public String getUrl() {
        return url;
    }
}