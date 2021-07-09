package contracts;

import com.owlike.genson.Genson;
import com.owlike.genson.GensonBuilder;
import contracts.Utils.Util;
import models.*;
import org.bouncycastle.util.Arrays;
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
import org.json.JSONObject;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

/**
 * Contextual information about the contract
 * MANDATORY annotation
 */
@Contract(
        name = "OlympusManager",
        info = @Info(
                title = "Olympus Manager ",
                description = "Smart Contract for IdP, VIdP, Services, etc management.",
                version = "1.0"
        )
)

@Default
public final class OlympusManager implements ContractInterface {
    // Serializacion JSON
    final Genson genson = new GensonBuilder().rename("context", "@context").create();

    /**
     * Consulta de schema definition
     * Get SchemaRegistration from ledger
     */
    @Transaction()
    public SchemaRegistration getschema(final Context ctx, final String idpID) {
        long beginning = System.nanoTime();
        ChaincodeStub stub = ctx.getStub();
        long beforeLedger = System.nanoTime();
        JSONObject query = new JSONObject().put("selector", new JSONObject()
                .put("docType", SchemaRegistration.class.getSimpleName())
                .put("idpID", idpID));
        QueryResultsIterator<KeyValue> queryResult = stub.getQueryResult(query.toString());
        System.out.println("getshema: getQueryResult: Time: " + (System.nanoTime() - beforeLedger));
        if (queryResult.iterator().hasNext()) {
            System.out.println("getshema: Time: " + (System.nanoTime() - beginning));
            return genson.deserialize(queryResult.iterator().next().getValue(), SchemaRegistration.class);
        } else {
            String errorMessage = String.format("IdP %s does not have any schema",
                    idpID);
            System.out.println(errorMessage);
            System.out.println("getshema: Time: " + (System.nanoTime() - beginning));
            throw new ChaincodeException(errorMessage, "Schema not found");
        }
    }


    @Transaction()
    public Object[] getschemas(final Context ctx, final String vIdpID) {
        long beginning = System.nanoTime();
        ChaincodeStub stub = ctx.getStub();
        long beforeLedger = System.nanoTime();
        String result = stub.getStringState(vIdpID);
        System.out.println("getshema: getQueryResult: Time: " + (System.nanoTime() - beforeLedger));
        if (!result.isEmpty()) {
            VIdPRegistration deserialize = genson.deserialize(result, VIdPRegistration.class);
            ArrayList<SchemaRegistration> schemas = new ArrayList<>();
            for (IdPService service : deserialize.getDid().getServices()) {
                schemas.add(getschema(ctx, service.getId()));
            }
            System.out.println("getshema: Time: " + (System.nanoTime() - beginning));
            return schemas.toArray();
        } else { // vidp no existe
            String errorMessage = String.format("Virtual IdP %s does not exist",
                    vIdpID);
            System.out.println(errorMessage);
            System.out.println("getshema: Time: " + (System.nanoTime() - beginning));
            throw new ChaincodeException(errorMessage, "Schema not found");
        }
    }

    /**
     * Registro de schema definition
     *
     * @param id
     * @param schema
     * @return
     */
    @Transaction()
    public SchemaRegistration addschema(final Context ctx, final String id,
                                        final String schema, String idpID) {
        long beginning = System.nanoTime();
        ChaincodeStub stub = ctx.getStub();

        // Check existence
        long beforeLedger = System.nanoTime();
        String schemaExist = stub.getStringState(id);
        System.out.println("addschema: getStringState: Time:" + (System.nanoTime() - beforeLedger));
        if (!schemaExist.isEmpty()) {
            String errorMessage = String.format("Schema with ID %s already exists. Use update to make changes", id);
            throw new ChaincodeException(errorMessage, "Schema already exists");
        }

        // Check idp existence
        IdPRegistration idP = getpartialidp(ctx, idpID);
        if (idP != null) {
            SchemaRegistration registration = new SchemaRegistration(schema, id, idpID);
            String schemaString = genson.serialize(registration);

            // update vidp
            /*JSONObject query = new JSONObject().put("selector", new JSONObject()
                    .put("docType", VIdPRegistration.class.getSimpleName())
                    .put("did.services", new JSONObject().put("$elemMatch", new JSONObject()
                            .put("id", idpID))));
            beforeLedger = System.nanoTime();
            QueryResultsIterator<KeyValue> queryResult = stub.getQueryResult(query.toString());
            System.out.println("addschema: getQueryResult: Time:" + (System.nanoTime() - beforeLedger));

            if (queryResult.iterator().hasNext()) {
                VIdPRegistration vidp = genson.deserialize(queryResult.iterator().next().getStringValue(), VIdPRegistration.class);
                beforeLedger = System.nanoTime();
                stub.putStringState(vidp.getDid().getId(), genson.serialize(vidp));
                System.out.println("addschema: putStringState: Time:" + (System.nanoTime() - beforeLedger));

            }*/
            beforeLedger = System.nanoTime();
            stub.putStringState(id, schemaString);
            System.out.println("addschema: putStringState: Time:" + (System.nanoTime() - beforeLedger));
            System.out.println("addschema: Time: " + (System.nanoTime() - beginning));
            return registration;
        }
        String errorMessage = String.format("idp with id %s does not exist",
                idpID);
        System.out.println(errorMessage);
        System.out.println("addschema: Time: " + (System.nanoTime() - beginning));

        throw new ChaincodeException(errorMessage, "idp does not exist");
    }

    @Transaction
    public SchemaRegistration updateschema(Context ctx, String id, final String schema) {
        long beginning = System.nanoTime();
        ChaincodeStub stub = ctx.getStub();
        long beforeLedger = System.nanoTime();
        String service = stub.getStringState(id);
        System.out.println("updateschema: getStringState: Time: " + (System.nanoTime() - beforeLedger));

        if (service.isEmpty()) {
            String errorMessage = String.format("Schema with ID %s does not exist", id);
            throw new ChaincodeException(errorMessage, "Schema does not exist");
        }
        SchemaRegistration deserialize = genson.deserialize(service, SchemaRegistration.class);
        if (schema.isEmpty())
            return deserialize;
        else {
            SchemaRegistration schemaRegistration = new SchemaRegistration(schema, id, deserialize.getIdpID());
            beforeLedger = System.nanoTime();
            stub.putStringState(id, genson.serialize(schemaRegistration));
            System.out.println("updateschema: putStringState: Time: " + (System.nanoTime() - beforeLedger));
            System.out.println("updateschema: Time: " + (System.nanoTime() - beginning));
            return schemaRegistration;
        }
    }


    // TODO how to verify ol_cred
    @Transaction
    public boolean verifycredential(Context ctx, String credential, String method, String schemaId) {
        // some kind of sweet code
        return true;
    }

    /**
     * Registro de IdPs. Comprueba que el DID no existe y actualiza el vIdP.
     *
     * @param DID       String
     * @param publicKey
     * @return
     */
    @Transaction
    public String addpartialidp(Context ctx, String DID, String publicKey, String vIdPID) {
        long beginning = System.nanoTime(); // time
        int idpCount;

        ChaincodeStub stub = ctx.getStub();
        DIDDocument idpID = genson.deserialize(DID, DIDDocument.class);
        long beforeLedger = System.nanoTime(); // time
        String idp = stub.getStringState(idpID.getId());
        System.out.println("addpartialidp: getStringState: Time: " + (System.nanoTime() - beforeLedger)); // time
        if (!idp.isEmpty()) { // comprueba que el DID no existe
            String errorMessage = String.format("IDP with ID %s already exists," +
                    " use update to modify the existing one.", idpID.getId());
            System.out.println("addpartialidp: Time: " + (System.nanoTime() - beginning));
            throw new ChaincodeException(errorMessage, "IDP already exists");
        }
        IdPRegistration registration = new IdPRegistration(idpID, Util.toRFC3339UTC(new Date()), "ACTIVE", publicKey);
        String registrationString = genson.serialize(registration);
        beforeLedger = System.nanoTime();
        stub.putStringState(idpID.getId(), registrationString);
        System.out.println("addpartialidp: putStringState: Time: " + (System.nanoTime() - beforeLedger));
        // richquery -> lowercase ( selector : { attributelistname : {$elemMatch : { attributename
        // : value } } } ) elemmatch porque es una lista
        // change vIdP
        VIdPRegistration vIdP;
        beforeLedger = System.nanoTime();
        String result = stub.getStringState(vIdPID);
        System.out.println("addpartialidp: getStringState: Time: " + (System.nanoTime() - beforeLedger));
        IdPService idPService = new IdPService(registration.getDid().getId(),
                idpID.getService().getServiceEndpoint(), publicKey);
        if (result.isEmpty()) {
            ArrayList<IdPService> services = new ArrayList<>();
            services.add(idPService);
            // empty
            vIdP = new VIdPRegistration(
                    new VIDPDocument(idpID.getContext(), vIdPID, services)
                    , Util.toRFC3339UTC(new Date()), "ACTIVE", null); // crear vIDP
            idpCount = 1;
        } else {
            vIdP = genson.deserialize(result, VIdPRegistration.class);
            vIdP.addService(idPService);
            idpCount = vIdP.getDid().getServices().size();
        }
        beforeLedger = System.nanoTime();
        stub.putStringState(vIdPID, genson.serialize(vIdP));
        System.out.println("addpartialidp: putStringState: Time: " + (System.nanoTime() - beforeLedger));
        System.out.println("addpartialidp: Time: " + (System.nanoTime() - beginning));
        return new JSONObject().put("IdP", registrationString).put("totalIdPs", idpCount).toString();
    }

    /**
     * @param id ID of the DID Document
     * @return the idp requested or null if not found
     */
    @Transaction
    public IdPRegistration getpartialidp(Context ctx, String id) {
        long beginning = System.nanoTime(); // time
        ChaincodeStub stub = ctx.getStub();
        long beforeLedger = System.nanoTime();
        String result = stub.getStringState(id);
        System.out.println("getpartialidp: getStringState: Time: " + (System.nanoTime() - beforeLedger));
        IdPRegistration deserialize = genson.deserialize(result,
                IdPRegistration.class);
        System.out.println("getpartialidp: Time: " + (System.nanoTime() - beginning));

        return deserialize;
    }

    @Transaction
    public IdPRegistration updatepartialidp(Context ctx, String id, String DID, String status,
                                            String publicKey, String virtualidpID) {
        long beginning = System.nanoTime();
        DIDDocument _DID = genson.deserialize(DID, DIDDocument.class);
        String _status = status, _publicKey = publicKey;
        ChaincodeStub stub = ctx.getStub();
        IdPRegistration idP = getpartialidp(ctx, id);
        if (idP == null) {
            String errorMessage = String.format("IDP with ID %s does not exists", id);
            System.out.println("updatepartialidp: Time: " + (System.nanoTime() - beginning));
            throw new ChaincodeException(errorMessage, "IDP does not exists");
        }
        if (DID.isEmpty()) {
            _DID = idP.getDid();
        }
        if (status.isEmpty()) {
            _status = idP.getStatus();
        }
        if (publicKey.isEmpty()) {
            _publicKey = idP.getPublicKey();
            // update vidp
            VIdPRegistration vidp = genson.deserialize(getvirtualidp(ctx, virtualidpID)[0], VIdPRegistration.class);
            vidp.getDid().updateIdP(new IdPService(id, idP.getDid().getService().getServiceEndpoint(), idP.getPublicKey()), publicKey);
        }
        IdPRegistration idPRegistration = new IdPRegistration(_DID, Util.toRFC3339UTC(new Date()), _status, _publicKey);
        long beforeLedger = System.nanoTime();
        stub.putStringState(_DID.getId(), genson.serialize(idPRegistration));
        System.out.println("updatepartialidp: putStringState: Time: " + (System.nanoTime() - beforeLedger));
        System.out.println("updatepartialidp: Time: " + (System.nanoTime() - beginning));

        return idPRegistration;
    }

    @Transaction
    public VIdPRegistration updatevirtualidp(Context ctx, String id, String DID, String status,
                                             String aggkey) {
        long beginning = System.nanoTime();
        VIDPDocument _DID = genson.deserialize(DID, VIDPDocument.class);
        String _status = status, _aggkey = aggkey;
        ChaincodeStub stub = ctx.getStub();
        VIdPRegistration vidp = genson.deserialize(getvirtualidp(ctx, id)[0], VIdPRegistration.class);
        if (DID.isEmpty()) {
            _DID = vidp.getDid();
        }
        if (status.isEmpty()) {
            _status = vidp.getStatus();
        }
        if (_aggkey.isEmpty()) {
            _aggkey = vidp.getAggpk();
        }
        VIdPRegistration vIdPRegistration = new VIdPRegistration(_DID, Util.toRFC3339UTC(new Date()), _status, _aggkey);
        long beforeLedger = System.nanoTime();
        stub.putStringState(_DID.getId(), genson.serialize(vIdPRegistration));
        System.out.println("updatevirtualidp: putStringState: Time: " + (System.nanoTime() - beforeLedger));
        System.out.println("updatevirtualidp:  Time: " + (System.nanoTime() - beginning));

        return vIdPRegistration;
    }

    /**
     * VIDP DISCOVERY
     *
     * @param ctx
     * @param id
     * @return
     */
    @Transaction
    public String[] getvirtualidp(Context ctx, String id) {
        long beginning = System.nanoTime();
        ChaincodeStub stub = ctx.getStub();
        JSONObject query;
        String[] vIdPRegistrations = {};

        if (id.isEmpty()) { // devolver todos los videos
            String[] array = {"_design/indexbyDocTypeDoc", "indexbyDocType"};
            query = new JSONObject()
                    .put("use_index", array)
                    .put("selector", new JSONObject()
                            .put("docType", VIdPRegistration.class.getSimpleName()));
            long beforeledger = System.nanoTime();
            QueryResultsIterator<KeyValue> queryResult = stub.getQueryResult(query.toString());
            System.out.println("gevirtualidp: getQueryResult: Time: " + (System.nanoTime() - beforeledger));
            for (KeyValue keyValue : queryResult)
                vIdPRegistrations = Arrays.append(vIdPRegistrations, keyValue.getStringValue());
        } else {
            String vidpString = stub.getStringState(id);
            vIdPRegistrations = Arrays.append(vIdPRegistrations, vidpString);
        }
        System.out.println("gevirtualidp: Time: " + (System.nanoTime() - beginning));
        return vIdPRegistrations;
    }

    /**
     * Service Registration
     *
     * @param ctx
     * @param DID
     * @param domain
     * @param predicates
     * @return
     */
    @Transaction
    public ServiceRegistration addservice(Context ctx, String DID, String domain, String predicates) {
        long beginning = System.nanoTime();
        ChaincodeStub stub = ctx.getStub();
        DIDDocument did = genson.deserialize(DID, DIDDocument.class);
        /*String service = stub.getStringState(servicePrefix + did.getId()); does it exists
        if (!service.isEmpty()) {
            String errorMessage = String.format("Service with ID %s already exists", did.getId());
            throw new ChaincodeException(errorMessage, "Service already exists");
        }*/

        ServiceRegistration registration = new ServiceRegistration(did, domain, predicates,
                Util.toRFC3339UTC(new Date()), "ACTIVE");
        String service = genson.serialize(registration);
        long beforeLedger = System.nanoTime();
        stub.putStringState(did.getId(), service);
        System.out.println("addservice: putStringState: Time: " + (System.nanoTime() - beforeLedger));
        System.out.println("addservice: Time: " + (System.nanoTime() - beginning));
        return registration;
    }

    @Transaction
    public ServiceRegistration updateservice(Context ctx, String id, String DID, String domain, String predicates,
                                             String status) {
        long beginning = System.nanoTime();
        String _domain = domain, _predicates = predicates, _status = status;
        DIDDocument _DID;
        ChaincodeStub stub = ctx.getStub();
        String service = stub.getStringState(id);
        if (service.isEmpty()) {
            String errorMessage = String.format("Service with ID %s does not exist", id);
            throw new ChaincodeException(errorMessage, "Service does not exist");
        }
        ServiceRegistration deserialize = genson.deserialize(service, ServiceRegistration.class);
        if (DID.isEmpty())
            _DID = deserialize.getDid();
        else
            _DID = genson.deserialize(DID, DIDDocument.class);
        if (domain.isEmpty())
            _domain = deserialize.getDomain();
        if (predicates.isEmpty())
            _predicates = deserialize.getPredicates();
        if (status.isEmpty())
            _status = deserialize.getStatus();

        long beforeLedger = System.nanoTime();
        ServiceRegistration serviceRegistration = new ServiceRegistration(_DID, _domain, _predicates,
                Util.toRFC3339UTC(new Date()), _status);
        stub.putStringState(id, genson.serialize(serviceRegistration));
        System.out.println("addservice: putStringState: Time: " + (System.nanoTime() - beforeLedger));
        System.out.println("addservice: Time: " + (System.nanoTime() - beginning));
        return serviceRegistration;
    }

    /**
     * Service Discovery
     *
     * @param ctx
     * @param id  did's id of service
     * @return the instance serviceRegistration
     */
    @Transaction
    public String[] getservice(Context ctx, String id) {
        long beginning = System.nanoTime();
        ChaincodeStub stub = ctx.getStub();
        JSONObject query;
        if (id.isEmpty()) { // devolver todos los servicios
            query = new JSONObject().put("selector", new JSONObject()
                    .put("docType", ServiceRegistration.class.getSimpleName()));
            long beforeledger = System.nanoTime();
            QueryResultsIterator<KeyValue> queryResult = stub.getQueryResult(query.toString());
            System.out.println("getservice: getQueryResult: Time: " + (System.nanoTime() - beforeledger));
            Iterator<KeyValue> iterator = queryResult.iterator();
            String[] vIdPRegistrations = {};
            while (iterator.hasNext()) {
                vIdPRegistrations = Arrays.append(vIdPRegistrations, iterator.next().getStringValue());
                if (vIdPRegistrations.length <= 0) {
                    String errorMessage = "There is no services";
                    System.out.println("getservice: Time: " + (System.nanoTime() - beginning));
                    throw new ChaincodeException(errorMessage, "Ledger empty");
                }
            }
            return vIdPRegistrations;
        } else { // only one
            long beforeLedger = System.nanoTime();
            String result = stub.getStringState(id);
            System.out.println("getservice: getStringState: Time: " + (System.nanoTime() - beforeLedger));
            if (result.isEmpty()) {
                String errorMessage = "Service does not exist";
                System.out.println("getservice: Time: " + (System.nanoTime() - beginning));
                throw new ChaincodeException(errorMessage, "Service does not exist");
            }
            System.out.println("getservice: Time: " + (System.nanoTime() - beginning));
            return new String[]{result};
        }
    }

    @Transaction
    public String serviceauditing(Context ctx) {

        long beginning = System.nanoTime();

        String[] service = getservice(ctx, "");
        String s = service[new Random().nextInt(service.length)];
        System.out.println("serviceauditing: Time: " + (System.nanoTime() - beginning));
        return s;
    }

    @Transaction
    public Event addevent(Context ctx, String title, String type, String body) {
        long beginning = System.nanoTime();

        ChaincodeStub stub = ctx.getStub();
        Event event = new Event(title, EventType.valueOf(type), body);

        long beforeLedger = System.nanoTime();
        stub.putStringState(String.valueOf(System.nanoTime()), genson.serialize(event));
        System.out.println("addevent: putStringState: Time: " + (System.nanoTime() - beforeLedger));
        System.out.println("addevent: Time: " + (System.nanoTime() - beginning));
        return event;
    }

    @Transaction
    public String[] getevent(Context ctx) {
        long beginning = System.nanoTime();

        ChaincodeStub stub = ctx.getStub();
        String[] array = {"_design/indexbyDocTypeDoc", "indexbyDocType"};
        String query = new JSONObject()
                .put("use_index", array)
                .put("selector", new JSONObject()
                        .put("docType", Event.class.getSimpleName())).toString();
        long beforeLedger = System.nanoTime();
        QueryResultsIterator<KeyValue> queryResult = stub.getQueryResult(query);
        System.out.println("getevent: getQueryResult: Time: " + (System.nanoTime() - beforeLedger));

        String[] logs = {};
        for (KeyValue keyValue : queryResult) logs = Arrays.append(logs, keyValue.getStringValue());
        System.out.println("getevent: Time: " + (System.nanoTime() - beginning));
        return logs;
    }
}