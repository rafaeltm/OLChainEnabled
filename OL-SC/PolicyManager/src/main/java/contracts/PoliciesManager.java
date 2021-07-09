package contracts;

import com.owlike.genson.Genson;
import models.PolicyRegistration;
import org.hyperledger.fabric.contract.Context;
import org.hyperledger.fabric.contract.ContractInterface;
import org.hyperledger.fabric.contract.annotation.Contract;
import org.hyperledger.fabric.contract.annotation.Default;
import org.hyperledger.fabric.contract.annotation.Info;
import org.hyperledger.fabric.contract.annotation.Transaction;
import org.hyperledger.fabric.shim.ChaincodeException;
import org.hyperledger.fabric.shim.ChaincodeStub;
import org.hyperledger.fabric.shim.ledger.KeyValue;
import org.hyperledger.fabric.shim.ledger.QueryResultsIterator;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

/**
 * Contextual information about the contract
 * MANDATORY annotation
 */
@Contract(
    name = "PolicyManager",
        info = @Info(
                title = "Policy management ",
                description = "Smart Contract for Policy registration, modification, elimination, etc.",
                version = "1.0"
        )
)

/**
 *
 * @see ChaincodeStub
 * @see ContractInterface
 */
@Default
public final class PoliciesManager implements ContractInterface {
    // Serializacion JSON
    private final Genson genson = new Genson();
    private static final String prefix = "POLICY_REGISTRATION_";

    /**
     * test Transaction definition
     */
    /*@Transaction()
    public void init(final Context ctx) {
        // stub can be used to call APIs to access to the ledger services, transaction context, or to invoke other
        chaincodes.
        ChaincodeStub stub = ctx.getStub();
        PublicInformation pubInfo = new PublicInformation("Datos test", true);

        // Serialize and save
        String info = genson.serialize(pubInfo);
        stub.putStringState("TEST", info);

    }*/

    /**
     * Get PolicyRegistration from ledger
     */
    @Transaction()
    public PolicyRegistration getPolicyRegistration(final Context ctx, final String policyName) {
        ChaincodeStub stub = ctx.getStub();
        // Por ejemplo key =
        String policyRegistration = stub.getStringState(prefix+policyName);

        if (!policyRegistration.isEmpty()) {
            return genson.deserialize(policyRegistration, PolicyRegistration.class);
        } else {
            String errorMessage = String.format("PolicyName %s does not exist",
                    policyName);
            System.out.println(errorMessage);
            throw new ChaincodeException(errorMessage, "Policy not found");
        }
    }

    /**
     * Put to ledger a generated share key  registration
     *
     */
    @Transaction()
    public PolicyRegistration createNewRegistration(final Context ctx, final String name, final String description,
                                                    final String predicates ) {
        ChaincodeStub stub = ctx.getStub();
        //PolicyRegistration record = genson.deserialize(PolicyRegistration, PolicyRegistration.class);

        // Check existence
        String PolicyRegistration = stub.getStringState(prefix+name);
        if (!PolicyRegistration.isEmpty()) { // TODO esto aqui no se aplica,
                                            // TODO si se genera una segunda vez pues se actualiza y .¿?
            // quiza está bien pero hay que meter un modify
            String errorMessage = String.format("Policy ID %s already exists", name);
            throw new ChaincodeException(errorMessage, "Policy IDº already exists");
        }
        PolicyRegistration registration = new PolicyRegistration(name,description,predicates);
        String info = genson.serialize(registration);
        stub.putStringState(name, info);
        return registration;
    } /**
     * Get all registrations from ledger.
     * @return List with JSON object key-value where key is PREFIX+hash and value is JSON object containing
     * {@link PolicyRegistration}.
     */
    @Transaction()
    public List<Object> getAllRegistrations(final Context ctx) {
        ChaincodeStub stub = ctx.getStub();

        QueryResultsIterator<KeyValue> list = stub.getStateByPartialCompositeKey(prefix);
        JSONArray policiesList = new JSONArray();
        for (KeyValue keyValue : list) {
            policiesList.put(new JSONObject().put(keyValue.getKey(), keyValue.getValue()));
        }

        try {
            list.close();
        } catch (Exception e) {
            String errorMessage = e.getMessage();
            System.out.println(errorMessage);
            throw new ChaincodeException(errorMessage, e.getCause());
        }
        return policiesList.toList();
    }

}
