import com.owlike.genson.Genson;
import com.owlike.genson.GensonBuilder;
import models.DIDDocument;
import models.EventType;
import models.Service;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.umu.controllers.BlockchainController;

public final class OlympusManagerTest {
        String VIDP = "did:umu:OL-virtualIDP:testing", P_IDP = "did:umu:OL-partialIDP:testing", SCHEMA =
                "did:umu:OL-PublicParameters:HorariosScheme-testing",
                SERVICE ="restaurnateExtremeño";
    @Test
    public void eltesting() {
        final Genson genson = new GensonBuilder().rename("context", "@context").create();
      /*  // add partial idp
        DIDDocument didDocument = new DIDDocument("https://www.w3.org/ns/did/v1", P_IDP,
                new Service("OL-Partial-IdP", "10.0.0.1"));
        DIDDocument didDocument1 = new DIDDocument("https://www.w3.org/ns/did/v1",
                SERVICE, new Service("Web Service", "Horarios"));
        String result = BlockchainController.getInstance().invokeContract("addpartialidp", // ADD PARTIAL
                 genson.serialize(didDocument), "VBIqHfJG+DcVqrcdAxCzJ8RLRHSbhWW5hMYSOgjNRRYpir5shXNYenfwbMGTph+I1iD1cONPeRXTkDsFNpfqxNASZmp1lISh6UBGcZuJmT4aTJmezqEaegp4CjoO17+gWOl2cIDenZ7X3Ef3GzEl51Eowby3eWYvIgKkOuVCrjy9CGCVseZ6+dJe4oI6T2SG5+gabFB6EjoLzgnZRZ6kUKFTgaeezRQ+9IXYVd2c10kgrYTyAWC",
               VIDP );
        System.out.println("add partial idp: " + result);
        // get partial idp
        result = BlockchainController.getInstance().invokeContract("getpartialidp", P_IDP);
        System.out.println("get partial idp: " + result);

        // get virtual idp
        result = BlockchainController.getInstance().invokeContract("getvirtualidp", "");
        System.out.println("get virtual idp: " + result);

        // add schema
        result = BlockchainController.getInstance().invokeContract("addschema", SCHEMA, "" +
                new JSONObject().put("attributeDefinitions", new JSONArray().put(new JSONObject().put("type", "Integer")
                        .put("id", "CourseYear").put("shortNAme","Course"))), P_IDP);
        System.out.println("add schema: " + result);
        // get schema
        result = BlockchainController.getInstance().invokeContract("getschema", P_IDP);
        System.out.println("get schema: " + result);
        // get virtual idp
        result = BlockchainController.getInstance().invokeContract("getvirtualidp", "");
        System.out.println("get virtual idp: " + result);
        // add service
        result = BlockchainController.getInstance().invokeContract("addservice",
                genson.serialize(didDocument1),  "Horarios", new JSONArray().put(new JSONObject()
                        .put("type", "Integer").put("id", "CourseYear").put("shortNAme","Course")).toString());
        System.out.println("add service: " + result);
        // get service
        result = BlockchainController.getInstance().invokeContract("getservice", "");
        System.out.println("get service: " + result);
        // add event
        String resultEvent = BlockchainController.getInstance().invokeContract("addevent", "" +
                "User Registered", EventType.INFORMATION.toString(), "" +
                "User 'rtorres@um.es' have registered");
        System.out.println("add event: " + resultEvent);
        resultEvent = BlockchainController.getInstance().invokeContract("getevent", "");
        System.out.println("get event: " + resultEvent);*/
        // getvidps
        String resultgetidps = BlockchainController.getInstance().invokeContract("getvidp", "");
        System.out.println("get vidps: " + resultgetidps);

        /*// update schema
        result = BlockchainController.getInstance().invokeContract("updateschema", SCHEMA,
                new JSONObject().put("attributeDefinitions", new JSONArray().put(new JSONObject().put("type", "String")
                        .put("id", "CourseYear").put("shortName","Course"))).toString());
        System.out.println("updateschema: " + result);
        // updateservice
        String lastresult = BlockchainController.getInstance().invokeContract("updateservice", SERVICE,
                "","Horarios", new JSONArray().put(new JSONObject()
                        .put("type", "Integer").put("id", "CourseYear").put("shortNAme","Course")).toString(), "INACTIVE");
        System.out.println("updateservice: " + lastresult);*/
    }
}
