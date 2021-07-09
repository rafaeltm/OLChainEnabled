package models;

import com.owlike.genson.annotation.JsonProperty;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

/**
 *
 */

@DataType
public final class DIDDocument {

    @Property
    @JsonProperty("@context")
    private final String context;

    @Property
    private final String id;

    @Property
    private final Service service;

    public DIDDocument(@JsonProperty("context") String context, @JsonProperty("id") String id,
                       @JsonProperty("service") Service service) {
        this.context = context;
        this.id = id;
        this.service = service;
    }

    public String getContext() {
        return context;
    }

    public String getId() {
        return id;
    }

    public Service getService() {
        return service;
    }
}
