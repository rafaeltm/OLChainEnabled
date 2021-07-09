import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.client.*;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.client.storage.InMemoryCredentialStorage;
import eu.olympus.model.*;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.usecase.model.SignIdentityProof;
import eu.olympus.util.Util;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.verifier.OLVerificationLibraryPS;
import eu.olympus.verifier.W3CPresentationVerifierOL;
import eu.olympus.verifier.W3CVerificationResult;
import eu.olympus.verifier.interfaces.W3CPresentationVerifier;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.apache.commons.codec.binary.Base64;
import org.junit.Ignore;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.*;


public class TestFlows {
    private static final byte[] seed = "random value random value random value random value random".getBytes();
    private static PABCConfigurationImpl[] configuration;
    private static long lifetime = 999999999;
    private static long allowedTimeDiff = 10000l;
    private static byte[] authKey = "verysecret".getBytes();
    private static final int serverCount = 3;
    private static String adminCookie;
    private static Logger logger = LoggerFactory.getLogger(TestFlows.class);


    @Ignore
    @Test
    public void testPabcPestoAlreadySetupLocal() throws Exception {
        Random rnd = new Random(1);
        byte[] rawCookie = new byte[64];
        rnd.nextBytes(rawCookie);
        adminCookie = Base64.encodeBase64String(rawCookie);

        List<PestoIdPRESTConnection> idps = new ArrayList<PestoIdPRESTConnection>();
        int serverCount = 3;
        long startTime = System.currentTimeMillis();
        int port = 9080;
        for (int i = 0; i < serverCount; i++) {
            PestoIdPRESTConnection rest = new PestoIdPRESTConnection("http://127.0.0.1:" + (port+i),
                    adminCookie, i);
            idps.add(rest);
        }

        Map<Integer, MSverfKey> publicKeys = new HashMap<>();
        for (Integer j = 0; j < serverCount; j++) {
            publicKeys.put(j, idps.get(j).getPabcPublicKeyShare());
        }
        PabcPublicParameters publicParam = idps.get(0).getPabcPublicParam();
        CredentialManagement credentialManagement = new PSCredentialManagement(true, new InMemoryCredentialStorage(), 60);
        ((PSCredentialManagement) credentialManagement).setup(publicParam, publicKeys, seed);

        ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1),
                ((RSAPublicKey) idps.get(0).getCertificate().getPublicKey()).getModulus());

        UserClient client = new PabcClient(idps, credentialManagement, cryptoModule);
        OLVerificationLibraryPS verificationLibrary = new OLVerificationLibraryPS();
        verificationLibrary.setup(idps, seed);
        W3CPresentationVerifier verifier = new W3CPresentationVerifierOL(verificationLibrary);
        testSimpleFlowPabc(client, verifier);
        //deleteUser(client, "test", "test");
    }

    private void deleteUser(UserClient client, String usr, String pwd) {
        try {
            client.deleteAccount(usr, usr, null, "NONE");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void testSimpleFlowPabc(UserClient client, W3CPresentationVerifier verifier) throws AuthenticationFailedException {
        try {
            client.deleteAccount("user_1", "password", null, "NONE");
        } catch (Exception e) {
            e.printStackTrace();
        }

        long start = System.currentTimeMillis();
        try{
            client.createUser("user_1", "password");
        } catch(UserCreationFailedException e) {
            fail("Failed to create user");
        }
        long creation = System.currentTimeMillis();

        // GET User, certificated, attributes from external source
        SignIdentityProof proof = getSignIdentityProof();
        try {
            // 	Prove identity with cached key
            client.addAttributes("user_1", "password", proof, null, "NONE");
        } catch(AuthenticationFailedException e) {
            fail("Failed to add attributes: " + e);
        }
        long attrAdded = System.currentTimeMillis();
        client.clearSession();

        long proveID = System.currentTimeMillis();
        String signedMessage="SignedMessage";
        List<Predicate> predicates = new ArrayList<>();
        Predicate predicate = new Predicate();
        predicate.setAttributeName("url:Organization");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        predicate = new Predicate();
        predicate.setAttributeName("url:DateOfBirth");
        predicate.setOperation(Operation.INRANGE);
        predicate.setValue(new Attribute(Util.fromRFC3339UTC("1988-01-05T00:00:00")));
        predicate.setExtraValue(new Attribute(Util.fromRFC3339UTC("2000-01-05T00:00:00")));
        predicates.add(predicate);
        predicate = new Predicate();
        predicate.setAttributeName("url:Role");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        predicate = new Predicate();
        predicate.setAttributeName("url:Mail");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        predicate = new Predicate();
        predicate.setAttributeName("url:AnnualSalary");
        predicate.setOperation(Operation.INRANGE);
        predicate.setValue(new Attribute(20000));
        predicate.setExtraValue(new Attribute(40000));
        predicates.add(predicate);

        Policy policy = new Policy(predicates, signedMessage);
        ObjectMapper mapper = new ObjectMapper();
        try {
            System.err.println(mapper.writeValueAsString(policy));
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        Policy verifierPolicy = new Policy(policy.getPredicates(), signedMessage);

        String token = client.authenticate("user_1", "password", policy, null, "NONE");
        //String token = client.authenticate("test", "test", policy, null, "NONE");
        System.out.println("TOKEN: " + token);
        client.clearSession();
        assertThat(verifier.verifyPresentationToken(token, verifierPolicy), is(W3CVerificationResult.VALID));

        long end = System.currentTimeMillis();
        logger.info("PABC Create: "+(creation-start));
        logger.info("PABC User attrs added: " +(attrAdded-creation));
        logger.info("PABC ID proofing: "+(proveID-creation));
        logger.info("PABC auth: "+(end-proveID));
        logger.info("PABC total time: "+((end-start))+" ms");
    }

    private SignIdentityProof getSignIdentityProof() {
        SignIdentityProof proof = null;
        try {
            URL url = new URL("http://localhost:3000/sign/bchainattrs");
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.setRequestProperty("Content-Type", "application/json");

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer content = new StringBuffer();
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            String resp = content.toString();
            JSONParser parser = new JSONParser();
            JSONObject json = (JSONObject) parser.parse(resp);
            proof = new SignIdentityProof(json);

            in.close();
            con.disconnect();
        } catch (ProtocolException e) {
            e.printStackTrace();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return proof;
    }

}
