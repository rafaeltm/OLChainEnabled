package contracts;

import com.owlike.genson.Genson;
import models.UserRegistration;
import org.hyperledger.fabric.contract.Context;
import org.hyperledger.fabric.contract.ContractInterface;
import org.hyperledger.fabric.contract.annotation.Contract;
import org.hyperledger.fabric.contract.annotation.Default;
import org.hyperledger.fabric.contract.annotation.Info;
import org.hyperledger.fabric.contract.annotation.Transaction;
import org.hyperledger.fabric.shim.ChaincodeException;
import org.hyperledger.fabric.shim.ChaincodeStub;
import org.hyperledger.fabric.shim.ledger.KeyModification;
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
    name = "UserManager",
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
public final class UserManager implements ContractInterface {
    // Serializacion JSON
    private final Genson genson = new Genson();
    private static final String registrationPrefix = "USER_REGISTRATION_";
    private static final String ackPrefix = "USER_ACK_";

    /**
     * test Transaction definition
     */
    /*@Transaction()
    public void init(final Context ctx) {
        // stub can be used to call APIs to access to the ledger services, transaction context, or to invoke other chaincodes.
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
    public UserRegistration getUserRegistrationInfo(final Context ctx, final String hash) {
        ChaincodeStub stub = ctx.getStub();
        // Por ejemplo key =
        String userRegistration = stub.getStringState(registrationPrefix +hash);

        if (!userRegistration.isEmpty()) {
            return genson.deserialize(userRegistration, UserRegistration.class);
        } else {
            String errorMessage = String.format("User with hash %s does not exist", hash);
            System.out.println(errorMessage);
            throw new ChaincodeException(errorMessage, "User Registration not found");
        }
    }

    /**
     * Put to ledger a user registration
     *
     */
    @Transaction()// TODO MAL,
    public UserRegistration createNewRegistration(final Context ctx, final String hash, final String timeStamp,
                                                    final String description) {
        ChaincodeStub stub = ctx.getStub();
        //UserRegistration record = genson.deserialize(userRegistration, UserRegistration.class);

        // Check existence
        String userRegistration = stub.getStringState(registrationPrefix +hash);
        if (!userRegistration.isEmpty()) {
            String errorMessage = String.format("User with hash %s already exists", hash);
            throw new ChaincodeException(errorMessage, "User already exists");
        }
        UserRegistration registration = new UserRegistration(timeStamp,description,hash);
        String info = genson.serialize(registration);
        stub.putStringState(hash, info);
        return registration;
    } /**
     * Get all registrations from ledger.
     * @return List with JSON object key-value where key is PREFIX+hash and value is JSON object containing {@link UserRegistration}.
     */
    @Transaction()
    public List<Object> getAllRegistrations(final Context ctx) {
        ChaincodeStub stub = ctx.getStub();

        QueryResultsIterator<KeyValue> list = stub.getStateByPartialCompositeKey(registrationPrefix);
        JSONArray userlist = new JSONArray();
        for (KeyValue keyValue : list) {
            userlist.put(new JSONObject().put(keyValue.getKey(), keyValue.getValue()));
        }

        try {
            list.close();
        } catch (Exception e) {
            String errorMessage = e.getMessage();
            System.out.println(errorMessage);
            throw new ChaincodeException(errorMessage, e.getCause());
        }
        return userlist.toList();
    }

    /**
     *
     * @param ctx
     * @param hash
     * @param policyName
     * @return status of the aproval {OK, error: policy not exist, error: user(hash) not found...}
     */
    @Transaction
    public String userPolicyACK(final Context ctx, final String hash, final String policyName, final String timestamp){
        ChaincodeStub stub = ctx.getStub();

        // user exist?
        String user = stub.getStringState(hash);
        if (user.isEmpty()){
            String errorMessage = "ERROR: user with hash" + hash+" does not exist.";
            System.out.println(errorMessage);
            throw new ChaincodeException(errorMessage, "ERROR: user not found");
        }
        // policy exist?
        String response = stub.invokeChaincodeWithStringArgs("PolicyManager", "getPolicyRegistration", policyName).getMessage();
        if (response.contains("not found")) {
            String errorMessage = "ERROR: policy with name" + policyName+" does not exist.";
            System.out.println(errorMessage);
            throw new ChaincodeException(errorMessage, "ERROR: policy not found");
        }
        String approval = "User with hash: " + hash + "approves the revelation of predicates in "+ policyName + " policy at " + timestamp;
        stub.putStringState(ackPrefix+hash+policyName, approval);

        return approval;
    }

    @Transaction
    public String getUserUniqueACK(final Context ctx, final String hash, final String policyName){
        ChaincodeStub stub = ctx.getStub();
        return stub.getStringState(ackPrefix+hash+policyName);
    }

    @Transaction
    public List<Object> getAllUserACK(final Context ctx, final String hash){
        ChaincodeStub stub = ctx.getStub();
        QueryResultsIterator<KeyValue> stateByPartialCompositeKey = stub.getStateByPartialCompositeKey(ackPrefix + hash);
        JSONArray objects = new JSONArray();
        for (KeyValue keyValue : stateByPartialCompositeKey) {
            objects.put(keyValue.getStringValue());
        }
        return objects.toList();
    }


}
