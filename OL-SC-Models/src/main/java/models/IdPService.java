package models;

import com.owlike.genson.annotation.JsonProperty;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

@DataType
public class IdPService {

    @Property
    private final String id;

    @Property
    private final String endpoint;

    @Property
    private final String pk;


    public IdPService(@JsonProperty("id") String id,@JsonProperty("endpoint") String endpoint,
                      @JsonProperty("pk") String pk) {
        this.id = id;
        this.endpoint = endpoint;
        this.pk = pk;
    }

    public IdPService(IdPService idPService, String newPublicKey) {
        this.id = idPService.getId();
        this.endpoint = idPService.getEndpoint();
        this.pk = newPublicKey;
    }

    public String getId() {
        return id;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public String getPk() {
        return pk;
    }

}
