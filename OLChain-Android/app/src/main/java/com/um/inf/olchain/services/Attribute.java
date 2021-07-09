package com.um.inf.olchain.services;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.um.inf.olchain.utils.Utils;

import java.util.Date;

import eu.olympus.model.AttributeType;
import eu.olympus.util.Util;

public class Attribute {

    @SerializedName("attr")
    @Expose
    private Object attr;
    @SerializedName("type")
    @Expose
    private String type;

    public Object getAttr() {
        if(this.getType().equals("DATE"))  {
            if(attr instanceof Double) {
                return new Date(Double.valueOf((double) attr).longValue());
            } else if(attr instanceof Long) {
                return new Date((long) attr);
            } else if (attr instanceof String) {
                return Util.fromRFC3339UTC((String) attr);
            }
        }

        if(this.getType().equals("INTEGER")) {
            if(attr instanceof Double) {
                return Double.valueOf((double) attr).intValue();
            } else if(attr instanceof Long) {
                return Long.valueOf((long) attr).intValue();
            }
        }

        return attr;
    }

    public void setAttr(Object attr) {
        this.attr = attr;
    }

    public String getType() {
        return type;
    }

    public eu.olympus.model.Attribute getOlympusAttribute() {
        return new eu.olympus.model.Attribute(getAttr(), AttributeType.valueOf(this.getType()));
    }

    public void setType(String type) {
        this.type = type;
    }

    @Override
    public String toString() {
        return getAttr().toString();
    }
}