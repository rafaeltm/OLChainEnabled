package models;

import com.owlike.genson.annotation.JsonProperty;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;
import org.json.JSONPropertyIgnore;

/**
 * This is the model of the asset
 */

@DataType
public final class ShareRegistration {

    @Property
    private final String timeStamp;

    @Property
    private final String description;

    @Property
    private final String PIdPId;

    public String getTimeStamp() {
        return timeStamp;
    }

    public ShareRegistration(@JsonProperty("timeStamp") String timeStamp, @JsonProperty("description") String description,
                             @JsonProperty("PIdPId") String PIdPId) {
        this.timeStamp = timeStamp;
        this.description = description;
        this.PIdPId = PIdPId;
    }

    public String getDescription() {
        return description;
    }

    public String getPIdPId() {
        return PIdPId;
    }
}
