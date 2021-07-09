package contracts;

import com.owlike.genson.Genson;
import models.ShareRegistration;
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
    name = "UserManagement",
        info = @Info(
                title = "User management ",
                description = "Smart Contract for user registration, modification, elimination, etc.",
                version = "1.0"
        )
)

/**
 *
 * @see ChaincodeStub
 * @see ContractInterface
 */
@Default
public final class SharesManager implements ContractInterface {
    // Serializacion JSON
    private final Genson genson = new Genson();
    private static final String prefix = "PIDP_REGISTRATION_";

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
     * Get userRegistration from ledger
     */
    @Transaction()
    public ShareRegistration getShareRegistration(final Context ctx, final String PIdP_Id) {
        ChaincodeStub stub = ctx.getStub();
        // Por ejemplo key =
        String userRegistration = stub.getStringState(prefix+PIdP_Id);

        if (!userRegistration.isEmpty()) {
            return genson.deserialize(userRegistration, ShareRegistration.class);
        } else {
            String errorMessage = String.format("Partial IdP with Id %s does not have credential generated",
                    PIdP_Id);
            System.out.println(errorMessage);
            throw new ChaincodeException(errorMessage, "Partial IdP registration  not found");
        }
    }

    /**
     * Put to ledger a generated share key registration
     *
     */
    @Transaction()
    public ShareRegistration createNewRegistration(final Context ctx, final String PIdP_ID, final String timeStamp,
                                                   final String description) {
        ChaincodeStub stub = ctx.getStub();
        //UserRegistration record = genson.deserialize(shareRegistration, UserRegistration.class);

        // Check existence
        String shareRegistration = stub.getStringState(prefix+PIdP_ID);
        if (!shareRegistration.isEmpty()) { // TODO esto aqui no se aplica,
                                            // TODO si se genera una segunda vez pues se actualiza y .¿?
            String errorMessage = String.format("Partial IdP with ID %s already exists", PIdP_ID);
            throw new ChaincodeException(errorMessage, "Partial registration already exists");
        }
        ShareRegistration registration = new ShareRegistration(timeStamp,description,PIdP_ID);
        String info = genson.serialize(registration);
        stub.putStringState(PIdP_ID, info);
        return registration;
    }

    /**
     * Get all registrations from ledger.
     * @return List with JSON object key-value where key is PREFIX+hash and value is JSON object containing
     * {@link ShareRegistration}.
     */
    @Transaction()
    public List<Object> getAllRegistrations(final Context ctx) {
        ChaincodeStub stub = ctx.getStub();

        QueryResultsIterator<KeyValue> list = stub.getStateByPartialCompositeKey(prefix);
        JSONArray sharesList = new JSONArray();
        for (KeyValue keyValue : list) {
            sharesList.put(new JSONObject().put(keyValue.getKey(), keyValue.getValue()));
        }

        try {
            list.close();
        } catch (Exception e) {
            String errorMessage = e.getMessage();
            System.out.println(errorMessage);
            throw new ChaincodeException(errorMessage, e.getCause());
        }
        return sharesList.toList();
    }

}
