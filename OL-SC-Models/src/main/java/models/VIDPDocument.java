package models;

import com.owlike.genson.annotation.JsonProperty;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

import java.util.ArrayList;

/**
 * This is the model of the asset
 */

@DataType
public final class VIDPDocument {
    @Property
    @JsonProperty("@context")
    private final String context;

    @Property
    private final String id;

    @Property
    private final ArrayList<IdPService> services;

    public VIDPDocument(@JsonProperty("@context") String context, @JsonProperty("id") String id,
                        @JsonProperty("services") ArrayList<IdPService> services) {
        this.context = context;
        this.id = id;
        this.services = services;
    }

    public String getContext() {
        return context;
    }

    public String getId() {
        return id;
    }

    public ArrayList<IdPService> getServices() {
        return services;
    }

    public void addService (IdPService idPService) {
        services.add(idPService);
    }

    public void updateIdP(IdPService idPService, String publicKey) {
        services.remove(idPService);
        services.add(new IdPService(idPService, publicKey));
    }
}
