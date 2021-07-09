package com.um.inf.olchain.rest.chainmodels;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class PublicParamsLedger {

    @SerializedName("schema")
    @Expose
    private Schema schema;
    @SerializedName("id")
    @Expose
    private String id;
    @SerializedName("docType")
    @Expose
    private String docType;
    @SerializedName("idpID")
    @Expose
    private String idpID;

    public Schema getSchema() {
        return schema;
    }

    public void setSchema(Schema schema) {
        this.schema = schema;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getDocType() {
        return docType;
    }

    public void setDocType(String docType) {
        this.docType = docType;
    }

    public String getIdpID() {
        return idpID;
    }

    public void setIdpID(String idpID) {
        this.idpID = idpID;
    }
}