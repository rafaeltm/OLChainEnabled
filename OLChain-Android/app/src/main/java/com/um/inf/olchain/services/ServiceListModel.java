package com.um.inf.olchain.services;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.um.inf.olchain.utils.Utils;

import java.util.LinkedList;
import java.util.List;

import eu.olympus.model.Policy;

public class ServiceListModel {
    @JsonProperty("name")
    @SerializedName("name")
    @Expose
    private String name;
    @JsonProperty("url")
    @SerializedName("url")
    @Expose
    private String url;
    @JsonProperty("image")
    @SerializedName("image")
    @Expose
    private String image;
    @JsonProperty("policy")
    @SerializedName("policy")
    @Expose
    private List<SignAPIPolicy> policy = null;

    private boolean ledgerPolicyCoincidence;

    public ServiceListModel(){}

    public ServiceListModel(String name, String url) {
        this.name = name;
        this.url = url;
        this.image = "https://www.startpage.com/av/proxy-image?piurl=https%3A%2F%2Fwww.samsung.com%2Fetc%2Fdesigns%2Fsmg%2Fglobal%2Fimgs%2Fsupport%2Fcont%2Fobj_ss.png&sp=1618586293Tc708a29b4f20a71756f1222f5d6bd20244230c329f9ce9f743383de349324413";
        this.policy = new LinkedList<>();
    }

    @JsonProperty("name")
    public String getName() {
        return name;
    }

    @JsonProperty("name")
    public void setName(String name) {
        this.name = name;
    }

    @JsonProperty("url")
    public String getUrl() {
        return url;
    }

    @JsonProperty("url")
    public void setUrl(String url) {
        this.url = url;
    }

    @JsonProperty("image")
    public String getImage() {
        return image;
    }

    @JsonProperty("image")
    public void setImage(String image) {
        this.image = image;
    }

    @JsonProperty("policy")
    public List<SignAPIPolicy> getPolicy() {
        return policy;
    }

    public boolean isledgerPolicyCoincidence() {
        return ledgerPolicyCoincidence;
    }

    public void setLedgerPolicyCoincidence(boolean ledgerPolicyCoincidence) {
        this.ledgerPolicyCoincidence = ledgerPolicyCoincidence;
    }

    public String policySummary() {
        String summary = "";
        for (SignAPIPolicy p: this.policy) {
            summary += p.policySummary();
            summary +=  "\n";
        }
        return summary.toUpperCase();
    }

    @Override
    public String toString() {
        return "{" +
                "name='" + name + '\'' +
                ", url='" + url + '\'' +
                ", image='" + image + '\'' +
                ", policy=" + policy +
                '}';
    }

    @JsonProperty("policy")
    public void setPolicy(List<SignAPIPolicy> policy) {
        this.policy = policy;
    }

    public Policy getOlympusPolicy() {
        return Utils.policyFromJsonString(this.policy);
    }
}
