package models;

import com.owlike.genson.annotation.JsonProperty;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

@DataType
public class VerificationMethod {

    @Property
    private final String type;

    @Property
    private final String id;

    @Property
    private final String publicKeyBase58;


    public VerificationMethod(@JsonProperty("type") String type, @JsonProperty("id") String id,
                              @JsonProperty("publicKeyBase58") String publicKeyBase58) {
        this.type = type;
        this.id = id;
        this.publicKeyBase58 = publicKeyBase58;
    }

    public String getType() {
        return type;
    }

    public String getId() {
        return id;
    }

    public String getPublicKeyBase58() {
        return publicKeyBase58;
    }
}
