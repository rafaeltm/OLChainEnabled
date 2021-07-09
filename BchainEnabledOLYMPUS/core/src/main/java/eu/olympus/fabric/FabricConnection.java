package eu.olympus.fabric;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.umu.controllers.BlockchainController;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class FabricConnection {
    private static Logger logger = LoggerFactory.getLogger(FabricConnection.class);
    private static String FILENAME = "TIMES.txt";
    public static Marker fabric = MarkerFactory.getMarker("FABRIC");
    public static int SERVERID;
    private static final String CHAINCODE = "OlympusManager";

    public static String invokeChaincode(String contractName, String methodName, String... params){
        BlockchainController instance = BlockchainController.getInstance();
        return instance.invokeContract("channel", contractName , methodName , params);
    }

    public static void writeTimeToFile(String methodName, double time, String additionalInfo) {
        try (FileWriter fstream = new FileWriter(SERVERID+"-"+FILENAME, true);
            BufferedWriter timesFile = new BufferedWriter(fstream)) {
            timesFile.write(String.format(methodName + ": " + time + " seconds " + additionalInfo + "%n"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void createFile() {
        try {
            File file = new File(SERVERID+"-"+FILENAME);
            if(!file.exists()) {
                file.createNewFile();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * IDP Events
     */
    public static void addOrUpdateIDP(String didID, String endpoint, String b64Pk, String vIdPID) {
        long start = System.nanoTime();
        String idpRegister = getIDP(didID);
        String test = "{" +
                "    \"id\":\"" + didID + "\"," +
                "    \"service\": {\n" +
                "        \"serviceEndpoint\":\""+endpoint+"\"," +
                "        \"type\": \"OL-Partial-IdP\"" +
                "    },\n" +
                "    \"context\": \"https://www.w3.org/ns/did/v1\"" +
                "}";

        String testUpdate = "{" +
                "    \"id\":\"" + didID + "\"," +
                "    \"service\": {\n" +
                "        \"serviceEndpoint\":\""+endpoint+"\"," +
                "        \"type\": \"OL-Partial-IdP\"" +
                "    },\n" +
                "    \"context\": \"https://www.w3.org/ns/did/v1\"" +
                "}";
        String response = "";
        if (idpRegister.isEmpty()) {
            response = invokeChaincode(CHAINCODE,"addpartialidp", test, b64Pk, vIdPID);
            logger.info(fabric,"New partial-IdP: " + response);
        } else { // Update if exists; ContractException
            response = invokeChaincode(CHAINCODE,"updatepartialidp", didID, testUpdate, "ACTIVE", b64Pk, vIdPID);
            logger.info(fabric,"Updated partial-IdP: " + response);
        }
        long total = System.nanoTime() - start;
        double seconds = (double)total / 1_000_000_000.0;
        writeTimeToFile("addOrUpdateIdP", seconds, "Total time");
        logger.info(fabric, "ADD/UPDT IDP: " + seconds + "(seg)");
    }

    public static String getIDP(String idpId) {
        long start = System.nanoTime();
        String response = invokeChaincode(CHAINCODE, "getpartialidp", idpId);
        long total = System.nanoTime() - start;
        double seconds = (double)total / 1_000_000_000.0;
        writeTimeToFile("getpartialidp", seconds, "Total time");
        logger.info(fabric, "GET IDP: " + response + "Total time: " + total);

        return response;
    }

    public static String getVIDP(String vIdpID) {
        long start = System.nanoTime();
        String response = invokeChaincode(CHAINCODE, "gevirtualidp", vIdpID);
        long total = System.nanoTime() - start;
        double seconds = (double)total / 1_000_000_000.0;
        writeTimeToFile("getvidp", seconds, "Total time");
        logger.info(fabric, "GET vIDP with id: " + vIdpID + " " + response + " Total time: " + total);

        return response;
    }

    public static void addOrUpdateCredentialSchema(String publicParams, String schemaId, String idPId) {
        long start = System.nanoTime();
        String result = invokeChaincode(CHAINCODE, "addschema",
                schemaId,
                publicParams,
                idPId);
        long total = System.nanoTime() - start;
        double seconds = (double)total / 1_000_000_000.0;
        writeTimeToFile("addschema", seconds, "Total time");
        logger.info(fabric, "OL-PublicParameters: " + result + " Total Time: " + total);
    }

    public static void getCredentialSchema() {
        long start = System.nanoTime();
        long total = System.nanoTime() - start;
        double seconds = (double)total / 1_000_000_000.0;
        writeTimeToFile("getschema", seconds, "Total time");
        logger.info(fabric, "GET SCHEMA: " + total);
    }

    /**
     * Client Events
     */

    public static void userPolicyEvaluationForService() {
        // TODO: Application level
        long start = System.nanoTime();
        long total = System.nanoTime() - start;
        double seconds = (double)total / 1_000_000_000.0;
        writeTimeToFile("policyeval", seconds, "Total time");
        logger.info(fabric, "USR POLICY EVAL: " + total);
    }

    /**
     * Services
     */
    public static void addOrUpdateService() {
        long start = System.nanoTime();
        long total = System.nanoTime() - start;
        double seconds = (double)total / 1_000_000_000.0;
        writeTimeToFile("addservice", seconds, "Total time");
        logger.info(fabric, "ADD SERVICE: " + total);
        //addservice
    }

    public static void getService() {
        // TODO: Application level
        // TODO: Also in the service deploy
        long start = System.nanoTime();
        long total = System.nanoTime() - start;
        double seconds = (double)total / 1_000_000_000.0;
        writeTimeToFile("getservice", seconds, "Total time");
        logger.info(fabric, "GET SERVICE: " + total);
        //getservice
    }

    /**
     * Event loggin
     */
    public static void addEvent(String eventName, String aditionalInfo) {
        long start = System.nanoTime();
        long total = System.nanoTime() - start;
        double seconds = (double)total / 1_000_000_000.0;
        writeTimeToFile("addevent", seconds, "Total time");
        logger.info(fabric, "ADD EVENT: " + total);
        // addevent
    }

    public static void getEvent() {
        long start = System.nanoTime();
        long total = System.nanoTime() - start;
        double seconds = (double)total / 1_000_000_000.0;
        writeTimeToFile("getevents", seconds, "Total time");
        logger.info(fabric, "GET EVENTS: " + total);
        //addevent
    }

    /**
     * get schemas from virtual idp
     */
    public static void getSchemas(String vIdPID) {
        long start = System.nanoTime();
        String result = invokeChaincode(CHAINCODE, "getschemas", vIdPID);
        long total = System.nanoTime() - start;
        double seconds = (double)total / 1_000_000_000.0;
        writeTimeToFile("getschemas", seconds, "Total time");
        logger.info(fabric, "OL-PublicParameters: " + result + " Total Time: " + total);
    }

}