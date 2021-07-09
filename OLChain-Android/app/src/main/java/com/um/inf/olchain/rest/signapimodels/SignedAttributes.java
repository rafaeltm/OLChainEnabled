package com.um.inf.olchain.rest.signapimodels;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class SignedAttributes {

    @SerializedName("signature")
    @Expose
    private String signature;
    @SerializedName("data")
    @Expose
    private Data data;

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public Data getData() {
        return data;
    }

    public void setData(Data data) {
        this.data = data;
    }

}