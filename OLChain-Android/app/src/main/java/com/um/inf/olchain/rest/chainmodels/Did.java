package com.um.inf.olchain.rest.chainmodels;

import java.util.List;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class Did {

    @SerializedName("@context")
    @Expose
    private String context;
    @SerializedName("id")
    @Expose
    private String id;
    @SerializedName("services")
    @Expose
    private List<Service> services = null;

    public String getContext() {
        return context;
    }

    public void setContext(String context) {
        this.context = context;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public List<Service> getServices() {
        return services;
    }

    public void setServices(List<Service> services) {
        this.services = services;
    }

}