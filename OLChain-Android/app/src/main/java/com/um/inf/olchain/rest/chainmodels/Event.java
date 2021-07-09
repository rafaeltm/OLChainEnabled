package com.um.inf.olchain.rest.chainmodels;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class Event {

    @SerializedName("body")
    @Expose
    private String body;
    @SerializedName("docType")
    @Expose
    private String docType;
    @SerializedName("eventType")
    @Expose
    private String eventType;
    @SerializedName("title")
    @Expose
    private String title;

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public String getDocType() {
        return docType;
    }

    public void setDocType(String docType) {
        this.docType = docType;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

}