package com.um.inf.olchain.rest.chainmodels;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class PartialIdp {
    @SerializedName("publicKey")
    @Expose
    private String publicKey;
    @SerializedName("spawnDate")
    @Expose
    private String spawnDate;
    @SerializedName("docType")
    @Expose
    private String docType;
    @SerializedName("did")
    @Expose
    private Did did;
    @SerializedName("status")
    @Expose
    private String status;

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getSpawnDate() {
        return spawnDate;
    }

    public void setSpawnDate(String spawnDate) {
        this.spawnDate = spawnDate;
    }

    public String getDocType() {
        return docType;
    }

    public void setDocType(String docType) {
        this.docType = docType;
    }

    public Did getDid() {
        return did;
    }

    public void setDid(Did did) {
        this.did = did;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}