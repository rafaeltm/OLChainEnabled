package verifier.rest;

import eu.olympus.model.Policy;

public class VerificationModel {

    private String token;
    private Policy policy;

    public VerificationModel() {
    }

    public VerificationModel(String token, Policy policy) {
        this.token = token;
        this.policy = policy;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Policy getPolicy() {
        return policy;
    }

    public void setPolicy(Policy policy) {
        this.policy = policy;
    }
}
