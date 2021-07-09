package models;

import com.owlike.genson.annotation.JsonProperty;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;
@DataType
public class Event {

    @Property
    private final String docType;

    @Property
    private final String title;

    @Property
    private final EventType eventType;

    @Property
    private final String body;

    public Event(@JsonProperty("title") String title,@JsonProperty("eventType") EventType eventType,@JsonProperty("body") String body) {
        this.title = title;
        this.eventType = eventType;
        this.body = body;

        this.docType = this.getClass().getSimpleName();
    }

    public String getTitle() {
        return title;
    }

    public EventType getEventType() {
        return eventType;
    }

    public String getBody() {
        return body;
    }

    public String getDocType() {
        return docType;
    }
}
