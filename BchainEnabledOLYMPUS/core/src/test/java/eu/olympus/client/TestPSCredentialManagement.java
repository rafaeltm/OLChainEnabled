package eu.olympus.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import VCModel.VerifiableCredential;
import VCModel.VerifiablePresentation;
import eu.olympus.model.*;
import eu.olympus.server.ThresholdPSSharesGenerator;
import eu.olympus.server.interfaces.*;
import eu.olympus.server.storage.InMemoryPestoDatabase;

import java.math.BigInteger;
import java.net.URI;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;

import eu.olympus.client.storage.InMemoryCredentialStorage;
import eu.olympus.util.W3CSerializationUtil;
import eu.olympus.util.pairingBLS461.PairingBuilderBLS461;
import eu.olympus.util.psmultisign.*;
import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import eu.olympus.TestParameters;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.util.multisign.MSpublicParam;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.util.pairingBLS461.ZpElementBLS461;
import eu.olympus.util.pairingInterfaces.Group2Element;
import eu.olympus.util.pairingInterfaces.ZpElement;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.FP12;


public class TestPSCredentialManagement {

    private ServerCryptoModule sCryptoModule = new SoftwareServerCryptoModule(new Random(1));
    private SoftwareClientCryptoModule cCryptoModule = null;
    private VerifiablePresentation token = null;

    private static final int nServers = 3;
    private static final long lifetime = 72000000;
    private static final long allowedTimeDifference = 10000l;
    private static final String key0 = "CnoKeAo6EisbfOFyTuoKozbyRISSwM85o5IXfiYZltcKGwoHoVFoHkBXJvnjn8YDczF/nZ8sdu/8QpHsMZX4IhI6B7/noK3X0V5VAZ7cHLJNypLqZWxSgqwMKDwj7Yk7k9L7j4Dk9S1u5zf2h3t5dQO04KT3111w1baUBRJ6CngKOhLrSyt1mP/V9WdMeO9EOSxLNKSGARwEHyktfSMVtoeDp9vMXNkUPJi70CV82k0rhF/3lFllvfuhFlQSOgk9TB/91EjG93BwdeZBKWDTkV3lhGGGCU2Lon4goo7Jmu4E0yAsy3Cw45/nCXziiu/l5vBiXm9/j68aegp4CjoQfH7QJG1AXoKkLQ0d7jWqFKV3eXpvGa7MiDB2miyW8y/SXxnT/ANYrLboa9YuZMQzUAL1F8MXI9b6EjoJlBYVWdBNKysboy8Ii4+ioiFmfTY4FlRSIZwLIj3V0gqscd0xjSSQKFxoBMtIe6oIGI4+eT/MvGBQIoEBCgNOb3cSegp4CjoABFx2HPX7IrN/u40TelnmU8QcMvCL4iiWmB3Pw2hq3eeBB8L+9ycKu9Xrl0pDCEpeKGNKcb4XCJwfEjoBaQxyimDo/Q/Q8j4fiWz/+DYcTF9aBlCxz8NMg4j9do2La6juzzckAcK22K23wzdxR4/ySjF2IAjOIoEBCgNBZ2USegp4CjoQ1TdDVXwg4HowwLLNwo3dhvs8BpC6EvUHKQQKb3eBwheajbWFrHWcciBqILv/fyWKzSMZ0STBiY+1EjoE//2Jqk0zpzJt10Vg2IZ/EZMhIPeVf21HfWGcTCEHuwYQEChVu4lrwRRZA7BbzXvUP0l9y3YSQjhnIoIBCgROYW1lEnoKeAo6AzuLurQtXjxmt9nHOisR7THToYYnL/Gvqh43HAHdpwv75iO1QtORycj7UL4vIAJop8VuvE+eAWkKoRI6BBMy5BG+qKntrFM5Z4k2pR7ToSp3zH4UYCKDNcZhXpiy0IjqpVG/4dGrciQY6x/gepIjOKl8ROOSrA==";
    private static final String param = "CAMSRAoyZXUub2x5bXB1cy51dGlsLnBhaXJpbmdCTFM0NjEuUGFpcmluZ0J1aWxkZXJCTFM0NjESA05vdxIDQWdlEgROYW1l";
    private static final byte[] seed = "random value random value random value random value random".getBytes();
    private PabcPublicParameters publicParameters;

    private Policy simplePolicy;

    @Before
    public void setupCrypto() throws Exception {
        RSAPrivateKey pk = TestParameters.getRSAPrivateKey1();
        BigInteger d = pk.getPrivateExponent();
        RSASharedKey keyMaterial = new RSASharedKey(pk.getModulus(), d, TestParameters.getRSAPublicKey1().getPublicExponent());
        Map<Integer, BigInteger> rsaBlindings = new HashMap<>();
        rsaBlindings.put(0, BigInteger.ONE);
        BigInteger oprfKey = new BigInteger("42");
        sCryptoModule.setupServer(new KeyShares(keyMaterial, rsaBlindings, oprfKey, null));
        cCryptoModule = new SoftwareClientCryptoModule(new Random(1), pk.getModulus());
        Map<String, Attribute> attributes = new HashMap<String, Attribute>();
        ZpElement zpElement = new ZpElementBLS461(new BIG(5));
        Group2Element g2Element = new PairingBuilderBLS461().getGroup2Generator();
        PSzkToken psZKToken = new PSzkToken(g2Element, g2Element, zpElement, new HashMap<String, ZpElement>(), zpElement, zpElement);

        VerifiableCredential vc = W3CSerializationUtil.generateVCredential(
                new Date(),
                attributes,
                null, false, null, null, null, null, new Date(), psZKToken.getEnconded(),
                "https://olympus-deployment.eu/example/context", "https://olympus-project.eu/example/validationSchema", "https://olympus-project.eu/example/encodingSchema", URI.create("did:meta:OL-vIdP"));
        token = W3CSerializationUtil.generatePresentation(vc, new Date(), "https://olympus-deployment.eu/example/context");

        simplePolicy = new Policy();
        simplePolicy.setPolicyId("SignedMessage");
        List<Predicate> predicates = new ArrayList<>();
        predicates.add(new Predicate("Name", Operation.REVEAL, null));
        simplePolicy.setPredicates(predicates);
        publicParameters = new PabcPublicParameters(generateAttributeDefinitions(), param);
    }

    private Set<AttributeDefinition> generateAttributeDefinitions() {
        Set<AttributeDefinition> res = new HashSet<>();
        res.add(new AttributeDefinitionString("Name", "Name", 0, 16));
        res.add(new AttributeDefinitionInteger("Age", "Age", 0, 123));
        res.add(new AttributeDefinitionDate("Now", "Now", "1900-01-01T00:00:00", "2100-09-01T00:00:00"));
        return res;
    }

    @Test
    public void testSetup() throws Exception {
        PSverfKey key = new PSverfKey(Base64.decodeBase64(key0));
        Map<Integer, MSverfKey> publicKeys = new HashMap<>();
        publicKeys.put(0, key);
        publicKeys.put(1, key);
        publicKeys.put(2, key);
        PSCredentialManagement credManagement = new PSCredentialManagement(true, new InMemoryCredentialStorage(), 60);
        credManagement.setup(publicParameters, publicKeys, seed);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetupBadParams() throws Exception {
        PSverfKey key = new PSverfKey(Base64.decodeBase64(key0));
        Map<Integer, MSverfKey> publicKeys = new HashMap<>();
        publicKeys.put(0, key);
        PSCredentialManagement credManagement = new PSCredentialManagement(true, new InMemoryCredentialStorage(), 60);
        credManagement.setup(new PabcPublicParameters(publicParameters.getAttributeDefinitions(), param.replace('a', 'b')), publicKeys, seed);
        fail();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetupBadNoOfKeys() throws Exception {
        Map<Integer, MSverfKey> publicKeys = new HashMap<>();
        PSCredentialManagement credManagement = new PSCredentialManagement(true, new InMemoryCredentialStorage(), 60);
        credManagement.setup(publicParameters, publicKeys, seed);
        fail();
    }

	@Test(expected = IllegalStateException.class)
	public void testGeneratePresentationTokenNoCredential() throws Exception {
		PSCredentialManagement cManager = new PSCredentialManagement(true,new InMemoryCredentialStorage(), 60);
		PSverfKey key = new PSverfKey(Base64.decodeBase64(key0));
		Map<Integer, MSverfKey> publicKeys = new HashMap<>();
		publicKeys.put(0, key);
		publicKeys.put(1, key);
		publicKeys.put(2, key);
		cManager.setup(publicParameters, publicKeys,seed);
		cManager.generatePresentationToken(simplePolicy);
		fail();
	}


    @Test(expected = IllegalStateException.class)
    public void credentialManagerGetPublicParamException() {
        PSCredentialManagement credentialManagement = new PSCredentialManagement(false, null, 60);
        credentialManagement.getPublicParams();
    }

    @Test(expected = IllegalStateException.class)
    public void credentialManagerGetPublicParamForOfflineException() {
        PSCredentialManagement credentialManagement = new PSCredentialManagement(false, null, 60);
        credentialManagement.getPublicParamsForOffline();
    }

    @Test
    public void testAuthenticateWithStoredCredential() throws Exception {
        List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
        TestIdP idp = new TestIdP(new InMemoryPestoDatabase(), null);
        idps.add(idp);
        CredentialManagement cManager = new PSCredentialManagement(true, new InMemoryCredentialStorage(), 60) {
            @Override
            public boolean checkStoredCredential() {
                return true;
            }

            @Override
            public VerifiablePresentation generatePresentationToken(Policy policy) {
                return token;
            }
        };
        PabcClient authClient = new PabcClient(idps, cManager, cCryptoModule);
        List<Predicate> predicates = new ArrayList<>();
        Predicate predicate = new Predicate();
        predicate.setAttributeName("Name");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        Policy policy = new Policy(predicates, "messageToBeSigned");

        String token = authClient.authenticate("username", "password", policy, null, "NONE");
        assertEquals(this.token.toJSONString(), token);
    }

    @Test
    public void testAuthenticateServerThrowsException() throws Exception {
        List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
        TestIdP idp = new TestIdP(new InMemoryPestoDatabase(), null) {
            @Override
            public String getCredentialShare(String username, byte[] cookie, long salt, byte[] signature, long timestamp) {
                throw new RuntimeException("simulated server failure");
            }
        };
        idps.add(idp);
        CredentialManagement cManager = new PSCredentialManagement(true, new InMemoryCredentialStorage(), 60);
        PabcClient authClient = new PabcClient(idps, cManager, cCryptoModule);
        List<Predicate> predicates = new ArrayList<>();
        Predicate predicate = new Predicate();
        predicate.setAttributeName("Name");
        predicate.setOperation(Operation.REVEAL);
        predicates.add(predicate);
        Policy policy = new Policy(predicates, "messageToBeSigned");

        String token = authClient.authenticate("username", "password", policy, null, "NONE");
        assertEquals("Failed", token);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCredentialManagementWrongCreation() throws Exception {
        PSCredentialManagement credentialManagement = new PSCredentialManagement(true, null, 60);
        fail("Should throw IllegalArgumentException");
    }

    @Test
    public void testCredentialManagementWrongOfflineSetup() throws Exception {
        PSCredentialManagement credentialManagement = new PSCredentialManagement(true, new InMemoryCredentialStorage(), 60);
        Set<String> attr = new HashSet<>();
        attr.add("test");
        MSpublicParam wrongPublicParam = new PSpublicParam(1, new PSauxArg("WrongPairingName", attr));
        MSpublicParam differentAttrPublicParam = new PSpublicParam(1, new PSauxArg(((PSauxArg) new PSpublicParam(publicParameters.getEncodedSchemePublicParam()).getAuxArg()).getPairingName(), attr));
        try {
            credentialManagement.setup(new PabcPublicParameters(publicParameters.getAttributeDefinitions(), differentAttrPublicParam.getEncoded()), null, seed);
            fail("Should throw IllegalArgumentException, publicParam");
        } catch (IllegalArgumentException e) {
        }
        try {
            credentialManagement.setup(new PabcPublicParameters(publicParameters.getAttributeDefinitions(), wrongPublicParam.getEncoded()), null, seed);
            fail("Should throw IllegalArgumentException, MS setup");
        } catch (IllegalArgumentException e) {
        }
    }

    @Test()
    public void testCredManagementPresentationTokenUnsupportedPredicate() throws Exception {
        String username = "userJoe";
        PestoDatabase database = new InMemoryPestoDatabase();
        Map<String, Attribute> userAttr = new HashMap<>();
        userAttr.put("Name", new Attribute("Joe"));
        userAttr.put("Age", new Attribute(21));
        userAttr.put("Now", new Attribute(new Date(System.currentTimeMillis())));
        Set<AttributeDefinition> res = new HashSet<>();
        res.add(new AttributeDefinitionString("Name", "Name", 1, 16));
        res.add(new AttributeDefinitionInteger("Age", "Age", 0, 123));
        res.add(new AttributeDefinitionDate("Now", "Now", "1900-01-01T00:00:00", "2100-09-01T00:00:00"));
        database.addUser(username, null, 1);
        database.addAttributes(username, userAttr);
        //Create and credentialGenerator module for each server.
        Map<Integer, CredentialGenerator> mapServers = new HashMap<>();
        PabcPublicParameters publicParams = null;
        for (int i = 0; i < 3; i++) {
            CredentialGenerator credentialServerModule = new ThresholdPSSharesGenerator(database, seed, i);
            PABCConfigurationImpl config = new PABCConfigurationImpl();
            config.setAttrDefinitions(res);
            config.setSeed(seed);
            config.setLifetime(lifetime);
            config.setAllowedTimeDifference(allowedTimeDifference);
            config.setServers(Arrays.asList("1", "2"));
            credentialServerModule.setup(config);
            publicParams = credentialServerModule.getPublicParam();
            mapServers.put(i, credentialServerModule);
        }
        MSpublicParam schemePublicParam = new PSpublicParam(publicParams.getEncodedSchemePublicParam());
        //Obtain publicKeyShares and aggregatedKey
        Map<Integer, MSverfKey> verificationKeyShares = new HashMap<>();
        MSverfKey[] verificationKeys = new MSverfKey[nServers];
        int i = 0;
        for (Integer id : mapServers.keySet()) {
            MSverfKey key = (MSverfKey) mapServers.get(id).getVerificationKeyShare();
            verificationKeys[i] = key;
            verificationKeyShares.put(id, key);
            i++;
        }
        PSms auxSignScheme = new PSms();
        auxSignScheme.setup(schemePublicParam.getN(), schemePublicParam.getAuxArg(), seed);
        MSverfKey aggregatedVerificationKey = auxSignScheme.kAggreg(verificationKeys);
        //Setup client module
        CredentialManagement credentialClientModule = new PSCredentialManagement(true, new InMemoryCredentialStorage(), 60);
        ((PSCredentialManagement) credentialClientModule).setup(publicParams, verificationKeyShares, seed);
        //*********Credential creation, proof of policy and verification***********
        String signedMessage = "signedMessage"; //Which would be this message in a real operation?
        //Policy creation
        List<Predicate> predicates = new ArrayList<>();
        predicates.add(new Predicate("Now", Operation.REVEAL, null));
        predicates.add(new Predicate("Age", Operation.REVEAL, null));
        Policy policy = new Policy(predicates, signedMessage);

        //Client receives a credential share from each IdP (simplified) and passes them to the credential manager
        Map<Integer, VerifiableCredential> credentialShares = new HashMap<>();
        long timestamp = System.currentTimeMillis();
        for (Integer id : mapServers.keySet())
            credentialShares.put(id, mapServers.get(id).createCredentialShare(username, timestamp));
        VerifiablePresentation zkPT = credentialClientModule.combineAndGeneratePresentationToken(credentialShares, policy);

        List<Predicate> predicatesWrong = new ArrayList<>();
        predicatesWrong.add(new Predicate("Now", Operation.GREATERTHAN, new Attribute(2)));
        Policy policyWrong = new Policy(predicatesWrong, signedMessage);
        try {
            credentialClientModule.combineAndGeneratePresentationToken(credentialShares, policyWrong);
            fail("Should throw IllegalArgumentException,  Unsupported policy combine");
        } catch (IllegalArgumentException e) {
        }
        try {
            credentialClientModule.generatePresentationToken(policyWrong);
            fail("Should throw IllegalArgumentException, Unsupported policy generate");
        } catch (IllegalArgumentException e) {
        }
    }

    private class TestIdP extends PestoIdPImpl {

        public TestIdP(Storage database, List<IdentityProver> identityProvers) throws Exception {
            super(database, identityProvers, new HashMap<String, MFAAuthenticator>(), new SoftwareServerCryptoModule(new Random(1)));
        }

        @Override
        public String getCredentialShare(String username, byte[] cookie, long salt, byte[] signature, long timestamp) {
            assertEquals("username", username);
            Map<String, Attribute> attributes = new HashMap<String, Attribute>();
            attributes.put("Name", new Attribute("John"));
            BIG x = new BIG(5);
            ZpElement zpElement = new ZpElementBLS461(x);
            Group2Element g2Element = new PairingBuilderBLS461().getGroup2Generator();

            PSsignature psSignature = new PSsignature(zpElement, g2Element, g2Element);
            PSCredential credential = new PSCredential(System.currentTimeMillis(), attributes, psSignature);
            return credential.getEncoded();
        }


        @Override
        public OPRFResponse performOPRF(String ssid, String username, ECP x, String mfaToken, String mfaType) {
            assertEquals("username", username);
            assertNotNull(ssid);
            assertNotNull(x);
            FP12 output = sCryptoModule.hashAndPair(ssid.getBytes(), x);
            return new OPRFResponse(output, ssid, "session");
        }
    }
}
