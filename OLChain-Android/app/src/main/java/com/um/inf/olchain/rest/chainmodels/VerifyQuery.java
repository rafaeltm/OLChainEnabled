package com.um.inf.olchain.rest.chainmodels;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import eu.olympus.model.Policy;

public class VerifyQuery {
    @SerializedName("vidpid")
    @Expose
    private String vidpid;
    @SerializedName("token")
    @Expose
    private String token;
    @SerializedName("policy")
    @Expose
    private Policy policy;

    public VerifyQuery() {
    }

    public VerifyQuery(String vidpid, String token, Policy policy) {
        this.vidpid = vidpid;
        this.token = token;
        this.policy = policy;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Policy getPolicy() {
        return policy;
    }

    public void setPolicy(Policy policy) {
        this.policy = policy;
    }

    public void setVidpid(String vidpid) {
        this.vidpid = vidpid;
    }

    public String getVidpid() {
        return vidpid;
    }
}
