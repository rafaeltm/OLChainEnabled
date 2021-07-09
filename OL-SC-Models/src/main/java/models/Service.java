package models;

import com.owlike.genson.annotation.JsonProperty;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

@DataType
public class Service {

    @Property
    private final String type;

    @Property
    private final String serviceEndpoint;


    public Service(@JsonProperty("type") String type,@JsonProperty("serviceEndpoint") String serviceEndpoint) {
        this.type = type;
        this.serviceEndpoint = serviceEndpoint;
    }

    public String getType() {
        return type;
    }

    public String getServiceEndpoint() {
        return serviceEndpoint;
    }
}
