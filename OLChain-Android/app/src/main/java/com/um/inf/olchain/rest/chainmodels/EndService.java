package com.um.inf.olchain.rest.chainmodels;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.util.List;

public class EndService {
    @SerializedName("date")
    @Expose
    private String date;
    @SerializedName("did")
    @Expose
    private Did did;
    @SerializedName("docType")
    @Expose
    private String docType;
    @SerializedName("domain")
    @Expose
    private String domain;
    @SerializedName("predicates")
    @Expose
    private List<ChainPredicate> predicates = null;
    @SerializedName("status")
    @Expose
    private String status;

    public String getDate() {
        return date;
    }

    public void setDate(String date) {
        this.date = date;
    }

    public Did getDid() {
        return did;
    }

    public void setDid(Did did) {
        this.did = did;
    }

    public String getDocType() {
        return docType;
    }

    public void setDocType(String docType) {
        this.docType = docType;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public List<ChainPredicate> getPredicates() {
        return predicates;
    }

    public void setPredicates(List<ChainPredicate> predicates) {
        this.predicates = predicates;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

}