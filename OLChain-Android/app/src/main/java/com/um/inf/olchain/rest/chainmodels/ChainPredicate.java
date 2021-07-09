package com.um.inf.olchain.rest.chainmodels;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class ChainPredicate {

    @SerializedName("attributeName")
    @Expose
    private String attributeName;
    @SerializedName("operation")
    @Expose
    private String operation;
    @SerializedName("value")
    @Expose
    private String value;
    @SerializedName("extraValue")
    @Expose
    private String extraValue;

    public String getAttributeName() {
        return attributeName;
    }

    public void setAttributeName(String attributeName) {
        this.attributeName = attributeName;
    }

    public String getOperation() {
        return operation;
    }

    public void setOperation(String operation) {
        this.operation = operation;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getExtraValue() {
        return extraValue;
    }

    public void setExtraValue(String extraValue) {
        this.extraValue = extraValue;
    }

}