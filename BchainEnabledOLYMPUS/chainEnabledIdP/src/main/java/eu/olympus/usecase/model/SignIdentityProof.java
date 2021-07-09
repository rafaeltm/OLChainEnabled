package eu.olympus.usecase.model;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.model.server.rest.IdentityProof;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;


public class SignIdentityProof extends IdentityProof {
    private String signature;
    private USCAttributes data;

    public SignIdentityProof() {}

    public SignIdentityProof(JSONObject json) {
        this.signature = json.get("signature").toString();
        try {
            JSONParser parser = new JSONParser();
            JSONObject jData = (JSONObject) parser.parse(json.get("data").toString());
            this.data = new USCAttributes(jData.get("url:Organization").toString(),
                    (String)jData.get("url:DateOfBirth"),
                    jData.get("url:Mail").toString(),
                    jData.get("url:Role").toString(),
                    jData.getAsNumber("url:AnnualSalary").intValue());
        } catch (ParseException e) {
            e.printStackTrace();
        }
    }

    public SignIdentityProof(String signature, USCAttributes data) {
        super();
        this.signature = signature;
        this.data = data;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public USCAttributes getData() {
        return data;
    }

    public void setData(USCAttributes data) {
        this.data = data;
    }

    @Override
    public String toString() {
        return "SignAPIResponse {" + '\n' +
                "signature (minimized) = " + signature.substring(0, 12) + "," + '\n' +
                "data = "  +'\t' + data + '\n' +
                '}';
    }

    public String toJson() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }
}