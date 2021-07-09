package models;

import com.owlike.genson.annotation.JsonProperty;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

/**
 * This is the model of the asset
 */

@DataType
public final class IdPRegistration {
    @Property
    private final String docType;

    @Property
    private final DIDDocument did;

    @Property
    private final String spawnDate;

    @Property
    private final String status;


    @Property
    private final String publicKey;


    public IdPRegistration(@JsonProperty("did") DIDDocument did, @JsonProperty("spawnDate") String spawnDate,
                           @JsonProperty("status") String status, @JsonProperty("publicKey") String publicKey) {
        this.did = did;
        this.spawnDate = spawnDate;
        this.status = status;
        this.publicKey = publicKey;
        this.docType = this.getClass().getSimpleName();
    }

    public DIDDocument getDid() {
        return did;
    }

    public String getSpawnDate() {
        return spawnDate;
    }

    public String getStatus() {
        return status;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getDocType() {
        return docType;
    }
}

