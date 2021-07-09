package models;

import com.owlike.genson.annotation.JsonProperty;
import org.bouncycastle.util.Arrays;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

/**
 * This is the model of the asset
 */

@DataType
public final class VIdPRegistration {

    @Property
    private final String docType;

    @Property
    private final VIDPDocument did;

    @Property
    private final String spawnDate;

    @Property
    private final String status;

    @Property
    private final String aggpk;

    public VIdPRegistration(@JsonProperty("did") VIDPDocument did, @JsonProperty("spawnDate") String spawnDate,
                            @JsonProperty("status") String status, @JsonProperty("aggpk") String aggpk) {
        this.docType = this.getClass().getSimpleName();
        this.did = did;
        this.spawnDate = spawnDate;
        this.status = status;
        this.aggpk = aggpk;
    }

    public VIDPDocument getDid() {
        return did;
    }

    public String getSpawnDate() {
        return spawnDate;
    }

    public String getStatus() {
        return status;
    }


    public String getAggpk() {
        return aggpk;
    }


    public String getDocType() {
        return docType;
    }


    public void addService(IdPService idPService) {
        did.addService(idPService);
    }

}

