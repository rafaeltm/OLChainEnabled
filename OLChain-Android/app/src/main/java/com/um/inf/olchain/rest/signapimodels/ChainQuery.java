package com.um.inf.olchain.rest.signapimodels;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class ChainQuery {
    @SerializedName("partialidpid")
    @Expose
    private String partialidpid;
    @SerializedName("vidpid")
    @Expose
    private String vidpid;
    @SerializedName("serviceid")
    @Expose
    private String serviceid;
    @SerializedName("body")
    @Expose
    private String eventdata;
    @SerializedName("title")
    @Expose
    private String eventname;
    @SerializedName("eventtype")
    @Expose
    private String eventtype;


    public ChainQuery() {
        this.eventdata = "";
        this.eventname = "";
        this.vidpid = "";
        this.partialidpid = "";
        this.serviceid = "";
    }

    public ChainQuery(String partialidpid, String vidpid, String serviceid, String eventdata, String eventname, String eventtype) {
        this.eventdata = eventdata;
        this.eventname = eventname;
        this.vidpid = vidpid;
        this.partialidpid = partialidpid;
        this.serviceid = serviceid;
        this.eventtype = eventtype;
    }

    public String getPartialidpid() {
        return partialidpid;
    }

    public void setPartialidpid(String partialidpid) {
        this.partialidpid = partialidpid;
    }

    public String getVidpid() {
        return vidpid;
    }

    public void setVidpid(String vidpid) {
        this.vidpid = vidpid;
    }

    public String getServiceid() {
        return serviceid;
    }

    public void setServiceid(String serviceid) {
        this.serviceid = serviceid;
    }

    public String getEventdata() {
        return eventdata;
    }

    public void setEventdata(String eventdata) {
        this.eventdata = eventdata;
    }

    public String getEventname() {
        return eventname;
    }

    public void setEventname(String eventname) {
        this.eventname = eventname;
    }

    public String getEventtype() {
        return eventtype;
    }

    public void setEventtype(String eventtype) {
        this.eventtype = eventtype;
    }

    @Override
    public String toString() {
        return "ChainQuery{" +
                "partialidpid='" + partialidpid + '\'' +
                ", vidpid='" + vidpid + '\'' +
                ", serviceid='" + serviceid + '\'' +
                ", eventdata='" + eventdata + '\'' +
                ", eventname='" + eventname + '\'' +
                ", eventtype='" + eventtype + '\'' +
                '}';
    }
}
