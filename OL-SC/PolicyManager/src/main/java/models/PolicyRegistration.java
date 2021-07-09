package models;

import com.owlike.genson.annotation.JsonProperty;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;
import org.json.JSONPropertyIgnore;

/**
 * This is the model of the asset
 */

@DataType
public final class PolicyRegistration {

    @Property
    private final String name; // TODO referencia al contexto como por ejemplo transporte.html?

    @Property
    private final String description; // TODO Idem, para dar contexto?

    @Property
    private final String predicates; // TODO da igual que ponga string que List<Predicate>, cuando se hace put o get
    // TODO se manda un JSON así que el {de}serialize lo haga el cliente.


    public PolicyRegistration(@JsonProperty("name") String name, @JsonProperty("description") String description,@JsonProperty("predicates") String predicates) {
        this.name = name;
        this.description = description;
        this.predicates = predicates;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getPredicates() {
        return predicates;
    }
}