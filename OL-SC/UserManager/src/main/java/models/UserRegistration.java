package models;

import com.owlike.genson.annotation.JsonProperty;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;
import org.json.JSONPropertyIgnore;

/**
 * This is the model of the asset
 */

@DataType
public final class UserRegistration {

    @Property
    private final String timeStamp;

    @Property
    private final String description;

    @Property
    private final String hash;

    public String getTimeStamp() {
        return timeStamp;
    }

    public UserRegistration(@JsonProperty("timeStamp") String timeStamp, @JsonProperty("description") String description,
                            @JsonProperty("hash") String hash) {
        this.timeStamp = timeStamp;
        this.description = description;
        this.hash = hash;
    }

    public String getDescription() {
        return description;
    }

    public String getHash() {
        return hash;
    }
}
