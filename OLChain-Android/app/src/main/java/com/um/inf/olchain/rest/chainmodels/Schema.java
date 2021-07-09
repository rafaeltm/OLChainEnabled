package com.um.inf.olchain.rest.chainmodels;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.util.List;

public class Schema {

    @SerializedName("attributeDefinitions")
    @Expose
    private List<AttributeDefinitionLedger> attributeDefinitions = null;
    @SerializedName("encodedSchemePublicParam")
    @Expose
    private String encodedSchemePublicParam;

    public List<AttributeDefinitionLedger> getAttributeDefinitions() {
        return attributeDefinitions;
    }

    public void setAttributeDefinitions(List<AttributeDefinitionLedger> attributeDefinitions) {
        this.attributeDefinitions = attributeDefinitions;
    }

    public String getEncodedSchemePublicParam() {
        return encodedSchemePublicParam;
    }

    public void setEncodedSchemePublicParam(String encodedSchemePublicParam) {
        this.encodedSchemePublicParam = encodedSchemePublicParam;
    }
}