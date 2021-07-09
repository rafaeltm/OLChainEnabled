package com.um.inf.olchain.rest.chainmodels;

import java.util.List;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class Vidp {
    @SerializedName("aggpk")
    @Expose
    private Object aggpk;
    @SerializedName("did")
    @Expose
    private Did did;
    @SerializedName("docType")
    @Expose
    private String docType;
    @SerializedName("idps")
    @Expose
    private List<String> idps = null;
    @SerializedName("schemas")
    @Expose
    private List<String> schemas = null;
    @SerializedName("spawnDate")
    @Expose
    private String spawnDate;
    @SerializedName("status")
    @Expose
    private String status;

    public Object getAggpk() {
        return aggpk;
    }

    public void setAggpk(Object aggpk) {
        this.aggpk = aggpk;
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

    public List<String> getIdps() {
        return idps;
    }

    public void setIdps(List<String> idps) {
        this.idps = idps;
    }

    public List<String> getSchemas() {
        return schemas;
    }

    public void setSchemas(List<String> schemas) {
        this.schemas = schemas;
    }

    public String getSpawnDate() {
        return spawnDate;
    }

    public void setSpawnDate(String spawnDate) {
        this.spawnDate = spawnDate;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

}