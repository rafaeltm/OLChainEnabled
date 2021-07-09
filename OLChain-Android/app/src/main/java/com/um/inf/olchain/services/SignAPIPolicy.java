package com.um.inf.olchain.services;


import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import eu.olympus.model.Operation;

import static eu.olympus.model.Operation.EQ;
import static eu.olympus.model.Operation.GREATERTHAN;
import static eu.olympus.model.Operation.INRANGE;
import static eu.olympus.model.Operation.LESSTHAN;
import static eu.olympus.model.Operation.REVEAL;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "attributeName",
        "operation",
        "value",
        "extra"
})
public class SignAPIPolicy {
    @JsonProperty("attributeName")
    @SerializedName("attributeName")
    @Expose
    private String attributeName;
    @JsonProperty("operation")
    @SerializedName("operation")
    @Expose
    private String operation;
    @JsonProperty("value")
    @SerializedName("value")
    @Expose
    private Attribute value;
    @JsonProperty("extra")
    @SerializedName("extra")
    @Expose
    private Attribute extra;

    public SignAPIPolicy() {
    }

    @JsonProperty("attributeName")
    public String getAttributeName() {
        return attributeName;
    }

    @JsonProperty("attributeName")
    public void setAttributeName(String attributeName) {
        this.attributeName = attributeName;
    }

    @JsonProperty("operation")
    public String getOperation() {
        return operation;
    }

    @JsonProperty("operation")
    public void setOperation(String operation) {
        this.operation = operation;
    }

    @JsonProperty("value")
    public Attribute getValue() {
        return value;
    }

    @JsonProperty("value")
    public void setValue(Attribute value) {
        this.value = value;
    }

    @JsonProperty("extra")
    public Attribute getExtra() {
        return extra;
    }

    @JsonProperty("extra")
    public void setExtra(Attribute extra) {
        this.extra = extra;
    }

    public String policySummary() {
        String description = this.attributeName + "\n\t -->" + this.operation;
        if(this.value != null) {
            description += "\n" + this.value.toString();
        }
        if(this.extra != null) {
            description += "\n" + this.extra.toString();
        }
        return description;
    }

    public Operation getOlympusOperation() {
        switch (operation) {
            case "LESSTHAN":
                return LESSTHAN;
            case "EQ":
                return EQ;
            case "GREATERTHAN":
                return GREATERTHAN;
            case "INRANGE":
                return INRANGE;
            default:
                return REVEAL;
        }
    }

}
