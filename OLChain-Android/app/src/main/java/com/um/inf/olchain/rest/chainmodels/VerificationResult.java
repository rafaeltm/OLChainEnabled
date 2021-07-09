package com.um.inf.olchain.rest.chainmodels;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class VerificationResult {
    @SerializedName("verification_result")
    @Expose
    private Boolean verificationResult;

    public Boolean getVerificationResult() {
        return verificationResult;
    }

    public void setVerificationResult(Boolean verificationResult) {
        this.verificationResult = verificationResult;
    }
}
