package models;

import com.owlike.genson.annotation.JsonProperty;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

/**
 * This is the model of the asset
 */

@DataType
public final class SchemaRegistration {
    // TODO no se lo que tiene un schema

    @Property
    private final String docType;

    @Property
    private final String id;

    @Property
    private final String schema; // raw schema?

    @Property
    private final String idpID;

    public SchemaRegistration(@JsonProperty("schema") String schema, @JsonProperty("id") String id,
                              @JsonProperty("idpID") String idpID) {
        this.docType = this.getClass().getSimpleName();
        this.schema = schema;
        this.id = id;
        this.idpID = idpID;

    }


    public String getSchema() {
        return schema;
    }

    public String getId() {
        return id;
    }

    public String getIdpID() {
        return idpID;
    }

    public String getDocType() {
        return docType;
    }
}