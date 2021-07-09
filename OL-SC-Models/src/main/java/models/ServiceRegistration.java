package models;

import com.owlike.genson.annotation.JsonProperty;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

/**
 * This is the model of the asset
 */

@DataType
public final class ServiceRegistration {

    @Property
    private final DIDDocument did;

    @Property
    private final String docType;

    @Property
    private final String domain;

    @Property
    private final String predicates; // or policyID

    @Property
    private final String date;

    @Property
    private final String status;

    public ServiceRegistration(@JsonProperty("did") DIDDocument did, @JsonProperty("domain") String domain,
                               @JsonProperty("predicates")  String predicates,
                               @JsonProperty("date")  String date,@JsonProperty("status") String status) {
        this.docType = this.getClass().getSimpleName();
        this.did = did;
        this.domain = domain;
        this.predicates = predicates;
        this.date = date;
        this.status = status;
    }

    public DIDDocument getDid() {
        return did;
    }

    public String getDomain() {
        return domain;
    }

    public String getPredicates() {
        return predicates;
    }

    public String getDate() {
        return date;
    }

    public String getStatus() {
        return status;
    }

    public String getDocType() {
        return docType;
    }
}

