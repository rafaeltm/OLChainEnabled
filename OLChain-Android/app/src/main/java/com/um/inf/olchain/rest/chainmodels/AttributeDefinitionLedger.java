package com.um.inf.olchain.rest.chainmodels;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class AttributeDefinitionLedger {

    @SerializedName("type")
    @Expose
    private String type;
    @SerializedName("id")
    @Expose
    private String id;
    @SerializedName("shortName")
    @Expose
    private String shortName;
    @SerializedName("minimumValue")
    @Expose
    private Integer minimumValue;
    @SerializedName("maximumValue")
    @Expose
    private Integer maximumValue;
    @SerializedName("minLength")
    @Expose
    private Integer minLength;
    @SerializedName("maxLength")
    @Expose
    private Integer maxLength;
    @SerializedName("minDate")
    @Expose
    private String minDate;
    @SerializedName("maxDate")
    @Expose
    private String maxDate;
    @SerializedName("granularity")
    @Expose
    private String granularity;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getShortName() {
        return shortName;
    }

    public void setShortName(String shortName) {
        this.shortName = shortName;
    }

    public Integer getMinimumValue() {
        return minimumValue;
    }

    public void setMinimumValue(Integer minimumValue) {
        this.minimumValue = minimumValue;
    }

    public Integer getMaximumValue() {
        return maximumValue;
    }

    public void setMaximumValue(Integer maximumValue) {
        this.maximumValue = maximumValue;
    }

    public Integer getMinLength() {
        return minLength;
    }

    public void setMinLength(Integer minLength) {
        this.minLength = minLength;
    }

    public Integer getMaxLength() {
        return maxLength;
    }

    public void setMaxLength(Integer maxLength) {
        this.maxLength = maxLength;
    }

    public String getMinDate() {
        return minDate;
    }

    public void setMinDate(String minDate) {
        this.minDate = minDate;
    }

    public String getMaxDate() {
        return maxDate;
    }

    public void setMaxDate(String maxDate) {
        this.maxDate = maxDate;
    }

    public String getGranularity() {
        return granularity;
    }

    public void setGranularity(String granularity) {
        this.granularity = granularity;
    }
}