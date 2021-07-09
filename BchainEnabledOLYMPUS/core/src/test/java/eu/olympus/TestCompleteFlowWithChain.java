package eu.olympus;

import eu.olympus.client.*;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.client.storage.InMemoryCredentialStorage;
import eu.olympus.model.*;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.IdentityProof;
import eu.olympus.server.*;
import eu.olympus.server.interfaces.*;
import eu.olympus.server.rest.*;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import eu.olympus.server.storage.InMemoryUserPasswordDatabase;
import eu.olympus.unit.server.TestIdentityProof;
import eu.olympus.unit.server.TestIdentityProver;
import eu.olympus.util.CommonCrypto;
import eu.olympus.util.Util;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.verifier.JWTVerifier;
import eu.olympus.verifier.OLVerificationLibraryPS;
import eu.olympus.verifier.W3CPresentationVerifierOL;
import eu.olympus.verifier.W3CVerificationResult;
import eu.olympus.verifier.interfaces.Verifier;
import eu.olympus.verifier.interfaces.W3CPresentationVerifier;
import org.apache.commons.codec.binary.Base64;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

//@Ignore
public class TestCompleteFlowWithChain {
	@Rule
	public final ExpectedException exception = ExpectedException.none();

	private static final byte[] seed = "random value random value random value random value random".getBytes();
	private static final byte[] seed0 = "random value random value random value random value random0".getBytes();
	private static final byte[] seed1 = "random value random value random value random value random1".getBytes();
	private static final byte[] seed2 = "random value random value random value random value random2".getBytes();

	private static PABCConfigurationImpl[] configuration;
	private static Verifier verifier;
	private static long lifetime = 72000000;
	private static long allowedTimeDiff = 20000l;
	private static long sessionLength = 600000l;
	private static String adminCookie;
	private static final int serverCount = 3;
	private static Map<Integer, PestoDatabase> databases = new HashMap<Integer, PestoDatabase>();

	private static Logger logger = LoggerFactory.getLogger(TestCompleteFlowWithChain.class);

	
	@BeforeClass
	public static void generatePestoConfigurations() {
		configuration = new PABCConfigurationImpl[3];
		byte[][] seeds=new byte[3][];
		seeds[0]=seed0;
		seeds[1]=seed1;
		seeds[2]=seed2;
		RSAPrivateCrtKey pk = (RSAPrivateCrtKey)TestParameters.getRSAPrivateKey2();
		BigInteger d = pk.getPrivateExponent();

		Random rnd = new Random(1);
		List<BigInteger> oprfKeys = new ArrayList<>(serverCount);
		List<BigInteger> rsaShares = new ArrayList<>(serverCount);
		BigInteger sum = BigInteger.ZERO;
		for(int i=0; i< serverCount-1; i++) {
			BigInteger currentRSAShare = new BigInteger(pk.getModulus().bitLength()+8*CommonCrypto.STATISTICAL_SEC_BYTES, rnd).mod(pk.getModulus());
			sum = sum.add(currentRSAShare);
			rsaShares.add(currentRSAShare);
			oprfKeys.add(new BigInteger(CommonCrypto.BITS_IN_GROUP+8*CommonCrypto.STATISTICAL_SEC_BYTES, rnd).mod(CommonCrypto.CURVE_ORDER));
		}
		rsaShares.add(d.subtract(sum));
		oprfKeys.add(new BigInteger(CommonCrypto.BITS_IN_GROUP+8*CommonCrypto.STATISTICAL_SEC_BYTES, rnd).mod(CommonCrypto.CURVE_ORDER));

		List<Map<Integer, BigInteger>> rsaBlindings = new ArrayList<Map<Integer, BigInteger>>(serverCount);
		List<Map<Integer, BigInteger>> oprfBlindings = new ArrayList<Map<Integer, BigInteger>>(serverCount);
		for(int i=0; i< serverCount; i++) {
			rsaBlindings.add(new HashMap<>(serverCount));
			oprfBlindings.add(new HashMap<>(serverCount));
		}
		for(int i=0; i< serverCount; i++) {
			for(int j = i; j<serverCount; j++) {
				if(i != j) {
					BigInteger current = new BigInteger(CommonCrypto.COMPUTATION_SEC_BYTES * 8, rnd);
					rsaBlindings.get(i).put(j, current);
					rsaBlindings.get(j).put(i, current);
					current = new BigInteger(CommonCrypto.COMPUTATION_SEC_BYTES * 8, rnd);
					oprfBlindings.get(i).put(j, current);
					oprfBlindings.get(j).put(i, current);
				}
			}
		}
		List<KeyShares> keyShares = new ArrayList<>();
		List<String> servers = new ArrayList<>();
		Map<String, Authorization> authorizationCookies = new HashMap<String, Authorization>();
		for(int i=0; i< serverCount; i++) {
			keyShares.add(new KeyShares(
					new RSASharedKey(pk.getModulus(), rsaShares.get(i), pk.getPublicExponent()),
					rsaBlindings.get(i), oprfKeys.get(i), oprfBlindings.get(i)));
			servers.add(Integer.toString(i));
			byte[] rawCookie = new byte[64];
			rnd.nextBytes(rawCookie);
			authorizationCookies.put(Base64.encodeBase64String(rawCookie), new Authorization("server"+i, Arrays.asList(new Role[] {Role.SERVER}), System.currentTimeMillis()+1000000l));
		}
		byte[] rawCookie = new byte[64];
		rnd.nextBytes(rawCookie);
		adminCookie = Base64.encodeBase64String(rawCookie);
		authorizationCookies.put(adminCookie, new Authorization("Administrator", Arrays.asList(new Role[] {Role.ADMIN}), System.currentTimeMillis()+1000000l));
		for(int i = 0; i< serverCount; i++) {
			configuration[i] = new PABCConfigurationImpl();
			List<String> otherServers=new LinkedList<>(servers);
			otherServers.remove(i);
			Map<String, Authorization> authorizedUsers = new HashMap<>();
			for(String cookie: authorizationCookies.keySet()) {
				if(("server"+i).equals(authorizationCookies.get(cookie).getId())) {
					configuration[i].setMyAuthorizationCookies(cookie);
				} else {
					authorizedUsers.put(cookie, authorizationCookies.get(cookie));
				}
			};
			Certificate cert = TestParameters.getRSA2Cert();
			verifier = new JWTVerifier(cert.getPublicKey());

			configuration[i].setAuthorizationCookies(authorizedUsers);
			configuration[i].setSessionLength(sessionLength);
			configuration[i].setServers(otherServers);
			configuration[i].setKeyMaterial(keyShares.get(i).getRsaShare());
			configuration[i].setRsaBlindings(keyShares.get(i).getRsaBlindings());
			configuration[i].setOprfBlindings(keyShares.get(i).getOprfBlindings());
			configuration[i].setOprfKey(keyShares.get(i).getOprfKey());
			configuration[i].setId(i);
			configuration[i].setRefreshKey(ByteBuffer.allocate(4).putInt(i).array());
			configuration[i].setAllowedTimeDifference(allowedTimeDiff);
			configuration[i].setWaitTime(1000);
			configuration[i].setLifetime(lifetime);;
			configuration[i].setAttrDefinitions(generateAttributeDefinitions());
			configuration[i].setSeed(seeds[i]);
			configuration[i].setPort(9080+i);
			configuration[i].setTlsPort(9090+i);
			configuration[i].setKeyStorePath(TestParameters.TEST_KEY_STORE_LOCATION);
			configuration[i].setTrustStorePath(TestParameters.TEST_TRUST_STORE_LOCATION);
			configuration[i].setKeyStorePassword(TestParameters.TEST_KEY_STORE_PWD);
			configuration[i].setTrustStorePassword(TestParameters.TEST_TRUST_STORE_PWD);
			configuration[i].setCert(cert);
			configuration[i].setRemoteShares(new HashMap<Integer, byte[]>());
			configuration[i].setDidSetup("test");
			configuration[i].setUseBchain(true);
			configuration[i].setVidpName("smartcampus");
		}
		for(int i = 0; i< serverCount; i++) {
			PestoRefresher refresher = new PestoRefresher(i, new SoftwareServerCryptoModule(new Random(i)));
			List<byte[]> shares = refresher.reshareMasterKeys(keyShares.get(i), serverCount);
			configuration[i].setLocalKeyShare(shares.remove(0));
			for(int j = 0; j < serverCount; j++) {
				if(i != j) {
					configuration[j].getRemoteShares().put(i, shares.remove(0));
				}
			}
		}
	}

	private static Set<AttributeDefinition> generateAttributeDefinitions() {
		Set<AttributeDefinition> res=new HashSet<>();
		res.add(new AttributeDefinitionString("Name","name",0,16));
		res.add(new AttributeDefinitionInteger("Age","age",0,123));
		res.add(new AttributeDefinitionString("Nationality","nationality",0,16));
		res.add(new AttributeDefinitionDate("DateOfBirth","dateOfBirth","1900-01-01T00:00:00","2020-09-01T00:00:00",DateGranularity.DAYS));
		return res;
	}

	private List<PestoIdP> setupIdPs( int amount) {
		if (amount != serverCount) {
			throw new IllegalArgumentException("Configuration only supports " + serverCount + " servers");
		}
		List<PestoIdP> idps = new ArrayList<PestoIdP>();
		databases = new HashMap<>();
		for(int i = 0; i< amount; i++) {
			databases.put(i,  new InMemoryPestoDatabase());
			PestoIdPImpl idp = null;
			List<IdentityProver> provers = new LinkedList<IdentityProver>();
			provers.add(new TestIdentityProver(databases.get(i)));
			SoftwareServerCryptoModule crypto = new SoftwareServerCryptoModule(new Random(i));
			try {
				Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
				mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(crypto));
				mfaAuthenticators.put("dummy", new DummyAuthenticator());
				idp = new PestoIdPImpl(databases.get(i), provers, mfaAuthenticators, crypto);
			} catch(Exception e) {
				fail("Failed to start IdP");
			}
			idps.add(idp);
		}
		return idps;
	}

	@Test
	public void testPestoRESTWithTLS() throws Exception{
		logger.info("Starting testPestoREST-TLS");
		int serverCount = 3;
		List<PestoIdP> idps = setupIdPs(serverCount);
		List<RESTIdPServer> restServers = new ArrayList<>();
		List<String> servlets=new LinkedList<>();
		servlets.add(PestoIdPServlet.class.getCanonicalName());
		for(int i = 0; i< serverCount; i++) {
			try {
				RESTIdPServer restServer = new RESTIdPServer();
				restServer.setIdP(idps.get(i));
				restServer.start(configuration[i].getPort(), servlets, configuration[i].getTlsPort(), configuration[i].getKeyStorePath(), configuration[i].getKeyStorePassword(), configuration[i].getKeyStorePassword());
				restServers.add(restServer);
			} catch (Exception e) {
				fail("Failed to start IdP");
			}
		}
		List<PestoIdP> restIdps = new ArrayList<>();
		for(int i = 0; i< serverCount; i++) {
			try {
				PestoIdPRESTConnection restConnection = new PestoIdPRESTConnection("https://127.0.0.1:"+(configuration[i].getTlsPort()),
						adminCookie, i);
				List<PestoIdP> others = new ArrayList<PestoIdP>();
				for(int j = 0; j< serverCount; j++) {
					if (j != i) {
						others.add(new PestoIdP2IdPRESTConnection("https://127.0.0.1:" + (configuration[j].getTlsPort()), j,
								configuration[i].getKeyStorePath(), configuration[i].getKeyStorePassword(),
								configuration[i].getTrustStorePath(), configuration[i].getTrustStorePassword(),
								configuration[i].getMyAuthorizationCookies()));
					}
				}
				for(String cookie: configuration[i].getAuthorizationCookies().keySet()) {
					((PestoIdPImpl) idps.get(i)).addSession(cookie, configuration[i].getAuthorizationCookies().get(cookie));
				}
				boolean res = ((PestoIdPImpl) idps.get(i)).setup("setup", configuration[i], others);
				assertTrue(res);
				restIdps.add(restConnection);
			} catch(Exception e) {
				fail("Failed to start IdP");
			}
		}
		Properties systemProps = System.getProperties();
		systemProps.put("javax.net.ssl.trustStore", TestParameters.TEST_TRUST_STORE_LOCATION);
		systemProps.put("javax.net.ssl.trustStorePassword", TestParameters.TEST_TRUST_STORE_PWD);
		System.setProperties(systemProps);

		UserClient client = new PestoClient(restIdps, new SoftwareClientCryptoModule(new Random(1), configuration[0].getKeyMaterial().getModulus()));
		testSimpleFlow(client, verifier);
		logger.info(":testPestoREST-TLS - starting accManagement");
		testAccManagement(client, verifier);
		client = new PestoClient(restIdps, new SoftwareClientCryptoModule(new Random(1), configuration[0].getKeyMaterial().getModulus()));
		logger.info(":testPestoREST-TLS - starting errorCases");
		testErrorCases(client, verifier);
		client = new PestoClient(restIdps, new SoftwareClientCryptoModule(new Random(1), configuration[0].getKeyMaterial().getModulus()));
		logger.info(":testPestoREST-TLS - starting refreshFlow");
		testRefreshFlow(client, verifier, restIdps);
		client = new PestoClient(restIdps, new SoftwareClientCryptoModule(new Random(1), configuration[0].getKeyMaterial().getModulus()));
		testMFAFlow(client, verifier);
		logger.info(":testPestoREST-TLS - starting MFAFlow");
		for(RESTIdPServer server:restServers){
			server.stop();
		}
	}

	@Test
	public void testPabcPestoREST() throws Exception{
		logger.info("Starting testPabcPestoREST");
		int serverCount = 3;
		List<PestoIdP> idps = setupIdPs(serverCount);
		List<RESTIdPServer> restServers = new ArrayList<>();
		List<String> servlets=new LinkedList<>();
		servlets.add(PestoIdPServlet.class.getCanonicalName());

		for(int i = 0; i< serverCount; i++) {
			try {
				RESTIdPServer restServer = new RESTIdPServer();
				restServer.setIdP(idps.get(i));
				restServer.start(configuration[i].getPort(), servlets, 0, null, null, null);
				restServers.add(restServer);
			} catch (Exception e) {
				fail("Failed to start IdP");
			}
		}
		List<PestoIdP> restIdps = new ArrayList<>();
		for(int i = 0; i< serverCount; i++) {
			try {
				PestoIdPRESTConnection restConnection = new PestoIdPRESTConnection("http://127.0.0.1:"+(configuration[i].getPort()),
						adminCookie, i);
				List<PestoIdP> others = new ArrayList<PestoIdP>();
				for(int j = 0; j< serverCount; j++) {
					if (j != i) {
						others.add(new PestoIdP2IdPRESTConnection("http://127.0.0.1:" + (configuration[j].getPort()), j,
								configuration[i].getMyAuthorizationCookies()));
					}
				}
				for(String cookie: configuration[i].getAuthorizationCookies().keySet()) {
					((PestoIdPImpl) idps.get(i)).addSession(cookie, configuration[i].getAuthorizationCookies().get(cookie));
				}
				boolean res = ((PestoIdPImpl) idps.get(i)).setup("setup", configuration[i], others);
				assertTrue(res);
				restIdps.add(restConnection);
			} catch(Exception e) {
				fail("Failed to start IdP");
			}
		}

		Map<Integer, MSverfKey> publicKeys = new HashMap<>();
		for (Integer j = 0; j< serverCount; j++){
			publicKeys.put(j, restIdps.get(j).getPabcPublicKeyShare());
		}
		PabcPublicParameters publicParam= restIdps.get(0).getPabcPublicParam();
		
		CredentialManagement credentialManagement=new PSCredentialManagement(true, new InMemoryCredentialStorage(), 60);
		((PSCredentialManagement)credentialManagement).setup(publicParam,publicKeys,seed);
		
		ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1), configuration[0].getKeyMaterial().getModulus());

		UserClient client = new PabcClient(restIdps, credentialManagement, cryptoModule);
		OLVerificationLibraryPS verificationLibrary = new OLVerificationLibraryPS();
		verificationLibrary.setup(idps,seed);
		W3CPresentationVerifier verifier= new W3CPresentationVerifierOL(verificationLibrary);
		testSimpleFlowPabc(client, verifier);
		testRefreshFlowPabc(client, verifier, restIdps);
		CredentialManagement credentialManagementWithoutStorage=new PSCredentialManagement(false, null,60);
		((PSCredentialManagement)credentialManagementWithoutStorage).setup(publicParam,publicKeys,seed);
		testMFAFlowPabc(new PabcClient(restIdps, credentialManagementWithoutStorage, cryptoModule), verifier);
		for(RESTIdPServer server:restServers){
			server.stop();
		}
	}

	private void testSimpleFlowPabc(UserClient client, W3CPresentationVerifier verifier) throws AuthenticationFailedException {
		long start = System.currentTimeMillis();
		try{
			client.createUser("user_1", "password");
		} catch(UserCreationFailedException e) {
			fail("Failed to create user");
		}
		long creation = System.currentTimeMillis();
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("Name", new Attribute("John Doe"));
		attributes.put("Nationality", new Attribute("DK"));
		attributes.put("Age",new Attribute(22));
		attributes.put("DateOfBirth",new Attribute(Util.fromRFC3339UTC("1998-01-05T00:00:00")));

		try {

			// 	Prove identity with cached key
			client.addAttributes("user_1", "password", new TestIdentityProof("proof", attributes), null, "NONE");
		} catch(AuthenticationFailedException e) {
			fail("Failed to prove identity: " + e);
		}
		client.clearSession();
		long addAttributesTime = System.currentTimeMillis();
		String signedMessage="SignedMessage";
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("Name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		predicate = new Predicate();
		predicate.setAttributeName("Age");
		predicate.setOperation(Operation.GREATERTHAN);
		predicate.setValue(new Attribute(18));
		predicate = new Predicate();
		predicate.setAttributeName("DateOfBirth");
		predicate.setOperation(Operation.INRANGE);
		predicate.setValue(new Attribute(Util.fromRFC3339UTC("1990-01-05T00:00:00")));
		predicate.setExtraValue(new Attribute(Util.fromRFC3339UTC("2000-01-05T00:00:00")));
		predicates.add(predicate);
		Policy policy = new Policy(predicates, signedMessage);
		Policy verifierPolicy = new Policy(policy.getPredicates(), signedMessage);

		String token = client.authenticate("user_1", "wrong password", policy, null, "NONE");
		client.clearSession();
		assertThat(verifier.verifyPresentationToken(token, verifierPolicy), is(W3CVerificationResult.INVALID_TOKEN));
		
		token = client.authenticate("user_1", "password", policy, null, "NONE");
		client.clearSession();

		assertThat(verifier.verifyPresentationToken(token, verifierPolicy), is(W3CVerificationResult.VALID));
		long end = System.currentTimeMillis();
		logger.info("PABC Create: "+(creation-start));
		logger.info("PABC prove: "+(addAttributesTime-creation));
		logger.info("PABC auth: "+(end-addAttributesTime));
		logger.info("PABC total time: "+((end-start))+" ms");
	}

	public void testSimpleFlow(UserClient client, Verifier verifier) throws AuthenticationFailedException {
		try{
			client.createUser("user_1", "password");
		} catch(UserCreationFailedException e) {
			fail("Failed to create user");
		}
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("Name", new Attribute("John Doe"));
		attributes.put("Nationality", new Attribute("DK"));
		attributes.put("Age",new Attribute(22));
		
		try {

			// Prove identity using the key cache
			client.addAttributes("user_1", "password",  new TestIdentityProof("proof", attributes), null, "NONE");
		} catch(AuthenticationFailedException e) {
			fail("Failed to prove identity: " + e);
		}
		client.clearSession();

		Map<String, Attribute> attributes2 = new HashMap<>();
		attributes2.put("Name", new Attribute("Jane Doe"));
		attributes2.put("Nationality", new Attribute("Se"));
		attributes2.put("Age",new Attribute(30));
		try{
			client.createUserAndAddAttributes("user_2", "password2", new TestIdentityProof("proof", attributes2));
			client.clearSession();
		} catch(UserCreationFailedException e) {
			fail("Failed to create user");
		}
		
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("Name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		predicate = new Predicate();
		predicate.setAttributeName("Age");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		Policy policy = new Policy(predicates, "testPolicy");
		String token = client.authenticate("user_1", "password", policy, null, "NONE");
		assertThat(verifier.verify(token), is(true));
		client.clearSession();

		try{ //
			client.authenticate("user_1", "bad_password", policy, null, "NONE");
			fail("Could authenticate with a bad password");
		} catch(AuthenticationFailedException e) {
		}
		client.clearSession();
		
		token = client.authenticate("user_2", "password2", policy, null, "NONE");
		assertThat(verifier.verify(token), is(true));
		client.clearSession();
	}

	public void testRefreshFlow(UserClient client, Verifier verifier, List<? extends PestoIdP> idps) throws Exception {
		// Create user to survive refresh

		try{
			client.createUser("aUser", "password");
		} catch(UserCreationFailedException e) {
			fail();
		}
		client.clearSession();

		// Perform refresh
		List<Future<Boolean>> res = new ArrayList<>();
		ExecutorService executorService = Executors.newFixedThreadPool(idps.size());
		for (PestoIdP idp : idps) {
				res.add(executorService.submit(() -> idp.startRefresh()));
		}
		for (Future<Boolean> current : res) {
			assertTrue(current.get());
		}

		// User already exists
		try{
			client.createUser("aUser", "password");
			fail();
		} catch(UserCreationFailedException e) {
			// Expected
		}
		client.clearSession();

		// User can still prove
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("Name", new Attribute("John Doe"));
		attributes.put("Nationality", new Attribute("Se"));
		attributes.put("Age",new Attribute(30));
		try {
			client.addAttributes("aUser", "password",  new TestIdentityProof("proof", attributes), null, "NONE");
		} catch(AuthenticationFailedException e) {
			fail("Failed to prove identity: " + e);
		}
		client.clearSession();

		// User can still reveal
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("Age");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		Policy policy = new Policy(predicates, "SignedMessage");
		String token = client.authenticate("aUser", "password", policy, null, "NONE");
		assertThat(verifier.verify(token), is(true));
		client.clearSession();

		// We can still make new users
		try{
			client.createUser("newUser", "password2");
		} catch(UserCreationFailedException e) {
			fail();
		}
		client.clearSession();

		// Ensure that a failed refresh does not break functionality
		res = new ArrayList<>();
		executorService = Executors.newFixedThreadPool(idps.size());
		res.add(executorService.submit(() -> idps.get(0).startRefresh()));
		for (Future<Boolean> current : res) {
			assertFalse(current.get());
		}
		// User already exists
		try{
			client.createUser("aUser", "password");
			fail();
		} catch(UserCreationFailedException e) {
		}

		// User can still prove
		try {
			client.addAttributes("aUser", "password",  new TestIdentityProof("proof", attributes), null, "NONE");
		} catch(AuthenticationFailedException e) {
			fail("Failed to prove identity: " + e);
		}
		client.clearSession();

		// User can still reveal
		policy = new Policy(predicates, "SignedMessage");
		token = client.authenticate("aUser", "password", policy, null, "NONE");
		assertThat(verifier.verify(token), is(true));
		client.clearSession();

		// We can still make new users
		try{
			client.createUser("newUser2", "password2");
		} catch(UserCreationFailedException e) {
			fail();
		}
		client.clearSession();
	}

	public void testRefreshFlowPabc(UserClient client, W3CPresentationVerifier verifier, List<PestoIdP> idps) throws Exception {
		// Create user to survive refresh
		try{
			client.createUser("aUser", "password");
		} catch(UserCreationFailedException e) {
			fail();
		}
		client.clearSession();

		// Perform refresh
		List<Future<Boolean>> res = new ArrayList<>();
		ExecutorService executorService = Executors.newFixedThreadPool(idps.size());
		for (PestoIdP idp : idps) {
			res.add(executorService.submit(() -> idp.startRefresh()));
		}
		for (Future<Boolean> current : res) {
			assertTrue(current.get());
		}

		// User already exists
		try{
			client.createUser("aUser", "password");
			fail();
		} catch(UserCreationFailedException e) {
		}


		// User can still prove
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("Name", new Attribute("John Doe"));
		attributes.put("Nationality", new Attribute("Se"));
		attributes.put("Age",new Attribute(30));
		try {
			client.addAttributes("aUser", "password",  new TestIdentityProof("proof", attributes), null, "NONE");
		} catch(AuthenticationFailedException e) {
			fail("Failed to prove identity: " + e);
		}
		client.clearSession();

		// User can still reveal
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("Name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		Policy policy = new Policy(predicates, "SignedMessage");
		String token = client.authenticate("aUser", "password", policy, null, "NONE");

		client.clearSession();
		assertThat(verifier.verifyPresentationToken(token, policy), is(W3CVerificationResult.VALID));

		// We can still make new users
		try{
			client.createUser("newUser", "password2");
		} catch(UserCreationFailedException e) {
			fail();
		}
		client.clearSession();
	}

	private void testMFAFlowPabc(UserClient client, W3CPresentationVerifier verifier) throws AuthenticationFailedException, UserCreationFailedException {
		try{
			client.createUser("user_mfa", "password");
			client.clearSession();
		} catch(UserCreationFailedException e) {
			fail("Failed to create user");
		}
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("Name", new Attribute("John Doe"));
		attributes.put("Nationality", new Attribute("DK"));
		attributes.put("Age",new Attribute(22));

		try {
			client.addAttributes("user_mfa", "password",  new TestIdentityProof("proof", attributes), null, "NONE");
			client.clearSession();
		} catch(AuthenticationFailedException e) {
			fail("Failed to prove identity: " + e);
		}
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("Name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		predicate = new Predicate();
		predicate.setAttributeName("Age");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		Policy policy = new Policy(predicates, "testPolicy");
		// Check that we can log on without MFA
		String token = client.authenticate("user_mfa", "password", policy, "", null);
		client.clearSession();
		assertThat(verifier.verifyPresentationToken(token, policy), is(W3CVerificationResult.VALID));

		// Check that we can not request a MFA with wrong password
		try {
			String secret = client.requestMFAChallenge("user_mfa", "bad_password", GoogleAuthenticator.TYPE);
			fail();
		}catch (Exception e) {
		}

		String challenge = client.requestMFAChallenge("user_mfa", "password", GoogleAuthenticator.TYPE);
		client.clearSession();
		// Check that MFA is not required while the registration process is active
		token = client.authenticate("user_mfa", "password", policy, "", "NONE");
		client.clearSession();
		assertThat(verifier.verifyPresentationToken(token, policy), is(W3CVerificationResult.VALID));

		String secondFactorToken;
		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
		//we need the proper private key to confirm mfa activation
		try {
			client.confirmMFA("user_mfa", "bad_password", secondFactorToken, GoogleAuthenticator.TYPE);
			fail();
		} catch(Exception e) {
		}
		//we need the proper challenge to confirm mfa activation
		try {
			client.confirmMFA("user_mfa", "password", "231312", GoogleAuthenticator.TYPE);
			fail();
		} catch(Exception e) {
		}
		// Cannot confirm with other token
		try {
			client.confirmMFA("user_mfa", "password", null, "NONE");
			fail();
		} catch(Exception e) {
		}

		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
		client.confirmMFA("user_mfa", "password", secondFactorToken, GoogleAuthenticator.TYPE);

		client.clearSession();

		String res;
		// Check that we cannot log on with a bad MFA code
		res = client.authenticate("user_mfa", "password", policy, "123123", GoogleAuthenticator.TYPE);
		if (!verifier.verifyPresentationToken(res, policy).equals(W3CVerificationResult.INVALID_TOKEN)) {
			fail();
		}

		// Check that we can log on using MFA

		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
		token = client.authenticate("user_mfa", "password", policy, secondFactorToken, GoogleAuthenticator.TYPE);

		assertThat(verifier.verifyPresentationToken(token, policy), is(W3CVerificationResult.VALID));

		// Check that the session token is locally cached
		token = client.authenticate("user_mfa", "password", policy, null, "NONE");
		assertThat(verifier.verifyPresentationToken(token, policy), is(W3CVerificationResult.VALID));

		client.clearSession();
		// Check that cookie gets removed after a clearSession
		res = client.authenticate("user_mfa", "password", policy, null, "NONE")  ;
		if (!verifier.verifyPresentationToken(res, policy).equals(W3CVerificationResult.INVALID_TOKEN)) {
			fail();
		}

		//we need the proper private key to remove mfa activation
		try {
			secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
			client.removeMFA("user_mfa", "bad_password", secondFactorToken, GoogleAuthenticator.TYPE);
			fail();
		} catch(Exception e) {
		}
		//we need the proper challenge to remove mfa activation
		try {
			client.removeMFA("user_mfa", "password", "231312", GoogleAuthenticator.TYPE);
			fail();
		} catch(Exception e) {
		}
		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
		client.removeMFA("user_mfa", "password", secondFactorToken, GoogleAuthenticator.TYPE);

		client.clearSession();

		// Check that you can authenticate without MFA
		token = client.authenticate("user_mfa", "password", policy, null, "NONE");
		assertThat(verifier.verifyPresentationToken(token, policy), is(W3CVerificationResult.VALID));

	}

	private void testAccManagement(UserClient client, Verifier verifier) throws AuthenticationFailedException {
		//simple flow has already been run, so we have some data to work with already
		//Try to get all attributes
		Map<String, Attribute> attributes = client.getAllAttributes("user_1", "password", null, "NONE");
		assertEquals(3, attributes.keySet().size());
		assertEquals(new Attribute("John Doe"), attributes.get("Name"));
		assertEquals(new Attribute("DK"), attributes.get("Nationality"));
		assertEquals(new Attribute(22), attributes.get("Age"));
		client.clearSession();

		//Delete Name and Age attribute
		List<String> attributesToDelete = new ArrayList<String>();
		attributesToDelete.add("Name");
		attributesToDelete.add("Age");
		//using wrong password
		try{
			client.deleteAttributes("user_1", "wrong_password", attributesToDelete, null, "NONE");
			fail();
		} catch(Exception e) {
			// expected
		}
		//using the proper password
		client.deleteAttributes("user_1", "password", attributesToDelete, null, "NONE");
		client.clearSession();
		attributes = client.getAllAttributes("user_1", "password", null, "NONE");
		client.clearSession();
		assertEquals(1, attributes.keySet().size());
		assertEquals(new Attribute("DK"), attributes.get("Nationality"));

		//try to get all attributes with wrong password
		try {
			attributes = client.getAllAttributes("user_1", "wrong_password", null, "NONE");
			fail();
		} catch (AuthenticationFailedException e) {
		}

		//Change password - wrong password
		try {
			client.changePassword("user_1", "incorrect_password", "newPassword", null, "NONE");
			fail();
		} catch (UserCreationFailedException e) {
			fail();
		} catch (AuthenticationFailedException e) {
			// Expected
		}

		//Change password - Proper password
		try {
			client.clearSession();
			client.changePassword("user_1", "password", "tempPassword", null, "NONE");
			client.changePassword("user_1", "tempPassword", "newPassword", null, "NONE");
		} catch (UserCreationFailedException|AuthenticationFailedException e) {
			fail();
		}
		client.clearSession();

		//Verify the new password works
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("Nationality");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		Policy policy = new Policy(predicates, "testPolicy");

		String token = client.authenticate("user_1", "newPassword", policy, null, "NONE");
		client.clearSession();
		assertThat(verifier.verify(token), is(true));

		//Try policy that cant be satisfies (with bad password)
		predicates = new ArrayList<>();
		predicate = new Predicate();
		predicate.setAttributeName("Name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		policy.setPredicates(predicates);
		try {
			token = client.authenticate("user_1", "password", policy, null, "NONE");
			fail();
		} catch(AuthenticationFailedException e) {
		}


		//Try policy that cant be satisfies (with proper password)
	//	policy = new Policy(revealAttributes);
		try {
			token = client.authenticate("user_1", "newPassword", policy, null, "NONE");
			fail();
		} catch(AuthenticationFailedException e) {
		}
		client.clearSession();

		//Try to delete account using wrong password
		try{
			client.deleteAccount("user_1", "wrong_Password", null, "NONE");
			fail();
		} catch(Exception e) {
		}

		//Try to delete account using proper password
		client.deleteAccount("user_1", "newPassword", null, "NONE");
		client.clearSession();

		predicates = new ArrayList<>();
		predicate = new Predicate();
		predicate.setAttributeName("Nationality");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		policy.setPredicates(predicates);
		//policy = new Policy(revealAttributes);
		try {
			token = client.authenticate("user_1", "newPassword", policy, null, "NONE");
			fail();
		} catch(AuthenticationFailedException e) {

		}

	}

	private void testMFAFlow(UserClient client, Verifier verifier) throws AuthenticationFailedException, UserCreationFailedException {
		try{
			client.createUser("user_mfa", "password");
			client.clearSession();
		} catch(UserCreationFailedException e) {
			fail("Failed to create user");
		}
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("Name", new Attribute("John Doe"));
		attributes.put("Nationality", new Attribute("DK"));
		attributes.put("Age",new Attribute(22));
		
		try {
			client.addAttributes("user_mfa", "password",  new TestIdentityProof("proof", attributes), null, "NONE");
			client.clearSession();
		} catch(AuthenticationFailedException e) {
			fail("Failed to prove identity: " + e);
		}
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("Name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		predicate = new Predicate();
		predicate.setAttributeName("Age");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		Policy policy = new Policy(predicates, "testPolicy");
		// Check that we can log on without MFA
		String token = client.authenticate("user_mfa", "password", policy, "", null);
		client.clearSession();
		assertThat(verifier.verify(token), is(true));
		
		// Check that we can not request a MFA for non-existing users
		try { 
			client.requestMFAChallenge("user_mfa", "password", null);
			fail();
		}catch (Exception e) {
		}
		
		// Check that we can not request a MFA with wrong password
		try { 
			client.requestMFAChallenge("user_mfa", "bad_password", GoogleAuthenticator.TYPE);
			fail();
		}catch (Exception e) {
		}
		
		String challenge = client.requestMFAChallenge("user_mfa", "password", GoogleAuthenticator.TYPE);
		client.clearSession();
		// Check that MFA is not required while the registration process is active
		token = client.authenticate("user_mfa", "password", policy, "", "NONE");
		assertThat(verifier.verify(token), is(true));
		// also check that starting a second MFA request flow does not break functionality
		String dummyChallenge = client.requestMFAChallenge("user_mfa", "password", "dummy");
		assertThat(dummyChallenge, is("alice"));		
		client.clearSession();
		
		String secondFactorToken;
		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
		//we need the proper private key to confirm mfa activation
		try {
			client.confirmMFA("user_mfa", "bad_password", secondFactorToken, GoogleAuthenticator.TYPE);
			fail();
		} catch(Exception e) {
		}
		//we need the proper challenge to confirm mfa activation
		try {
			client.confirmMFA("user_mfa", "password", "231312", GoogleAuthenticator.TYPE);
			fail();
		} catch(Exception e) {
		}
		// Cannot confirm with other token
		try {
			client.confirmMFA("user_mfa", "password", null, "NONE");
			fail();
		} catch(Exception e) {
		}
		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
		client.confirmMFA("user_mfa", "password", secondFactorToken, GoogleAuthenticator.TYPE);

		client.clearSession();

		// Check that we cannot log on with a bad MFA code
		try {
			client.authenticate("user_mfa", "password", policy, "123123", GoogleAuthenticator.TYPE);
			fail();
		}catch(AuthenticationFailedException e) {
		}

		// Check that we can log on using MFA
		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
		token = client.authenticate("user_mfa", "password", policy, secondFactorToken, GoogleAuthenticator.TYPE);
		assertThat(verifier.verify(token), is(true));
		
		// Check that the session token is locally cached
		token = client.authenticate("user_mfa", "password", policy, null, "NONE");
		assertThat(verifier.verify(token), is(true));
		client.clearSession();

		// Check that cookie gets removed after a clearSession
		try {
			client.authenticate("user_mfa", "password", policy, null, "NONE")  ;
			fail();
		}catch(AuthenticationFailedException e) {
		}


		// check that the second MFA mechanism can also be used
		try {
			client.authenticate("user_mfa", "password", policy, "bob", "dummy"); 
			fail(); //the dummy MFA is not yet active
		}catch(AuthenticationFailedException e) {
		}
		try {
			client.confirmMFA("user_mfa", "password", "bob", "dummy"); 
			fail(); //we cannot activate a second MFA 
		}catch(AuthenticationFailedException e) {
		}
		
		try {
			client.authenticate("user_mfa", "password", policy, "bob", "dummy"); 
			fail(); //we cannot use the inactive MFA 
		}catch(AuthenticationFailedException e) {
		}
		client.clearSession();

		//check that changing passwords, does not affect MFA
		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
		client.changePassword("user_mfa", "password", "newPassword", secondFactorToken, GoogleAuthenticator.TYPE);
		client.clearSession();

		// ie. we should not be able to login without MFA
		try {
			client.authenticate("user_mfa", "newPassword", policy, null, "NONE")  ;
			fail();
		}catch(AuthenticationFailedException e) {
		}
		
		//and MFA should still work
		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
		token = client.authenticate("user_mfa", "newPassword", policy, secondFactorToken, GoogleAuthenticator.TYPE);
		assertThat(verifier.verify(token), is(true));
		client.clearSession();
		
		//we need the proper private key to remove mfa activation
		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);

		try {
			client.removeMFA("user_mfa", "bad_password", secondFactorToken, GoogleAuthenticator.TYPE);
			fail();
		} catch(Exception e) {
		}
		//we need the proper challenge to remove mfa activation
		try {
			client.removeMFA("user_mfa", "newPassword", "231312", GoogleAuthenticator.TYPE);
			fail();
		} catch(Exception e) {
		}



		secondFactorToken = new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))).generateTOTP(challenge);
		client.removeMFA("user_mfa", "newPassword", secondFactorToken, GoogleAuthenticator.TYPE);
		client.clearSession();

		// Check that you can authenticate without MFA
		token = client.authenticate("user_mfa", "newPassword", policy, null, "NONE");
		assertThat(verifier.verify(token), is(true));
		client.clearSession();
		
		// Check that we can activate and use the dummy mfa:
		client.confirmMFA("user_mfa", "newPassword", "bob", "dummy");
		client.clearSession();
		token = client.authenticate("user_mfa", "newPassword", policy, "bob", "dummy");
		assertThat(verifier.verify(token), is(true));
		client.clearSession();

		
	}

	private void testErrorCases(UserClient client, Verifier verifier) throws AuthenticationFailedException {
		//The acc flow has been run, removing all data from the db
		try {
			client.createUser("user", "password");
		} catch(Exception e) {
			fail();
		}

		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("Name", new Attribute("John Doe"));
		attributes.put("Nationality", new Attribute("DK"));
		attributes.put("Age",new Attribute(22));
		TestIdentityProof proof = new TestIdentityProof("proof", attributes);


		//Prove identity: Id proof without suitable Id proving component
		try {
			BadIdentityProof badProof = new BadIdentityProof();
			client.addAttributes("user", "password", badProof, null, "NONE");
			fail();
		} catch (AuthenticationFailedException e) {
		}
		client.clearSession();

		//Prove identity: No Id proof
		try {
			client.addAttributes("user", "password", null, null, "NONE");
			fail();
		} catch (AuthenticationFailedException e) {
		}
		client.clearSession();

		//Prove identity: No user
		try {
			client.addAttributes("some_other_user", "password", proof, null, "NONE");
			fail();
		} catch (AuthenticationFailedException e) {
		}

		//Prove identity: wrong password
		try {
			client.addAttributes("user", "wrong_password", proof, null, "NONE");
			fail();
		} catch (AuthenticationFailedException e) {
		}
		//Authenticate: Can not satisfy policy
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("Email");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		Policy policy = new Policy(predicates, "testPolicy");
		try{ //
			client.authenticate("user", "password", policy, null, "NONE");
			fail("Produced token containing email attribute");
		} catch(AuthenticationFailedException e) {
		}
		client.clearSession();

		//GetAllAttributes: No user
		try {
			Map<String, Attribute> attrib = client.getAllAttributes("some_other_user", "password", null, "NONE");
			assertEquals(0, attrib.size());
		} catch (AuthenticationFailedException e) {
		}

		//GetAllAttributes: wrong password
		try {
			Map<String, Attribute> attrib = client.getAllAttributes("user", "wrong_password", null, "NONE");
			assertEquals(0, attrib.size());
		} catch (AuthenticationFailedException e) {
		}

		List<String> attributesToDelete = new ArrayList<String>();
		attributesToDelete.add("Name");
		attributesToDelete.add("Nationality");
		//DeleteAttributes: no user
		try {
			client.deleteAttributes("some_other_user", "password", attributesToDelete, null, "NONE");
			fail();
		} catch (AuthenticationFailedException e) {
		}

		//DeleteAttributes: wrong password
		try {
			client.deleteAttributes("user", "wrong_password", attributesToDelete, null, "NONE");
			fail();
		} catch (AuthenticationFailedException e) {
		}

		//DeleteAccount: no user
		try {
			client.deleteAccount("some_other_user", "password", null, "NONE");
			fail();
		} catch (AuthenticationFailedException e) {
		}

		//DeleteAccount: wrong password
		try {
			client.deleteAccount("user", "wrong_password", null, "NONE");
			fail();
		} catch (AuthenticationFailedException e) {
		}
	}
	
	private class BadIdentityProof extends IdentityProof {
	
		public BadIdentityProof() {
		}
		@Override
		public String getStringRepresentation() {
			return null;
		}
	}
	
	private class DummyAuthenticator implements MFAAuthenticator {
		@Override
		public boolean isValid(String token, String secret) {
			return "bob".equals(token) && "alice".equals(secret);
		}

		@Override
		public String generateTOTP(String secret) {
			return "bob";
		}

		@Override
		public String generateSecret() {
			return "alice";
		}

		@Override
		public String combineSecrets(List<String> secrets) {
			return "alice";
		}
	}
}
