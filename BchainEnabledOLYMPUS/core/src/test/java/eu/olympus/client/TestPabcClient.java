package eu.olympus.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import VCModel.VerifiableCredential;
import VCModel.VerifiablePresentation;
import eu.olympus.TestParameters;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.client.storage.InMemoryCredentialStorage;
import eu.olympus.model.Attribute;
import eu.olympus.model.KeyShares;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;

import eu.olympus.util.W3CSerializationUtil;
import eu.olympus.util.pairingBLS461.PairingBuilderBLS461;
import org.junit.Before;
import org.junit.Test;

import eu.olympus.model.RSASharedKey;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import eu.olympus.util.pairingBLS461.ZpElementBLS461;
import eu.olympus.util.pairingInterfaces.Group2Element;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.psmultisign.PSsignature;
import eu.olympus.util.psmultisign.PSzkToken;
import java.math.BigInteger;
import java.net.URI;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;

import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.FP12;


public class TestPabcClient {
	
	private ServerCryptoModule sCryptoModule = new SoftwareServerCryptoModule(new Random(1));
	private SoftwareClientCryptoModule cCryptoModule = null;
	private VerifiablePresentation token = null;
	private Map<String, MFAAuthenticator> mfaAuthenticators;
	private final static String user = "username";
	private final static String password = "password";
	
	@Before
	public void setupCrypto() throws Exception{
		RSAPrivateKey pk = TestParameters.getRSAPrivateKey2();
		BigInteger d = pk.getPrivateExponent();
		RSASharedKey keyMaterial = new RSASharedKey(pk.getModulus(), d, TestParameters.getRSAPublicKey2().getPublicExponent());
		Map<Integer, BigInteger> rsaBlindings = new HashMap<>();
		rsaBlindings.put(0, BigInteger.ONE);
		BigInteger oprfKey = new BigInteger("42");
		sCryptoModule.setupServer(new KeyShares(keyMaterial, rsaBlindings, oprfKey, null));
		cCryptoModule = new SoftwareClientCryptoModule(new Random(1), pk.getModulus());
		
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		ZpElement zpElement = new ZpElementBLS461(new BIG(5));
		Group2Element g1Element = new PairingBuilderBLS461().getGroup2Generator();
		
		PSzkToken psZKToken = new PSzkToken(g1Element, g1Element, zpElement, new HashMap<String, ZpElement>(), zpElement, zpElement);

		VerifiableCredential vc = W3CSerializationUtil.generateVCredential(
				new Date(),
				attributes,
				null, false, null, null, null, null, new Date(), psZKToken.getEnconded(),
				"https://olympus-deployment.eu/example/context", "https://olympus-project.eu/example/validationSchema", "https://olympus-project.eu/example/encodingSchema", URI.create("did:meta:OL-vIdP"));
		token = W3CSerializationUtil.generatePresentation(vc, new Date(), "https://olympus-deployment.eu/example/context");

		mfaAuthenticators = new HashMap<>();
		mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(cCryptoModule));
	}

	@Test
	public void testAuthenticate() throws Exception {
		List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
		TestIdP idp = new TestIdP(null);
		
		idps.add(idp);
		CredentialManagement cManager = new PSCredentialManagement(true, new InMemoryCredentialStorage(), 60) {
			@Override
			public VerifiablePresentation combineAndGeneratePresentationToken(Map<Integer, VerifiableCredential> credentialShares,
					Policy policy) {
				return token;
			}
		};
		PabcClient authClient = new PabcClient(idps, cManager, cCryptoModule);
		
		
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		Policy policy = new Policy(predicates, "messageToBeSigned");


		String token = authClient.authenticate("username", "password", policy, null, "NONE");
		assertEquals(this.token.toJSONString(), token);
	}

	@Test
	public void testAuthenticateWithStoredCredential() throws Exception {
		List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
		TestIdP idp = new TestIdP(null);
		
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
		predicate.setAttributeName("name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		Policy policy = new Policy(predicates, "messageToBeSigned");
		
		String token = authClient.authenticate("username", "password", policy, null, "NONE");
		assertEquals(this.token.toJSONString(), token);
	}
	
	@Test
	public void testAuthenticateServerThrowsException() throws Exception {
		List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
		TestIdP idp = new TestIdP(null) {
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
		predicate.setAttributeName("name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		Policy policy = new Policy(predicates, "messageToBeSigned");
		
		String token = authClient.authenticate("username", "password", policy, null, "NONE");
		assertEquals("Failed",token);
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testMissingRequestMFAChallenge() throws Exception {
		List<PestoIdPImpl> idps = new ArrayList<>();
		TestIdP idp = new TestIdP(null);
		idps.add(idp);
		CredentialManagement cManager = new PSCredentialManagement(true, new InMemoryCredentialStorage(), 60);
		PabcClient authClient = new PabcClient(idps, cManager, cCryptoModule);
		authClient.requestMFAChallenge(user, password, GoogleAuthenticator.TYPE);
		fail();
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testMissingConfirmMFA() throws Exception {
		List<PestoIdPImpl> idps = new ArrayList<>();
		TestIdP idp = new TestIdP(null);
		idps.add(idp);
		CredentialManagement cManager = new PSCredentialManagement(true, new InMemoryCredentialStorage(), 60);
		PabcClient authClient = new PabcClient(idps, cManager, cCryptoModule);
		authClient.confirmMFA(user, password, "none", GoogleAuthenticator.TYPE);
		fail();
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testMissingRemoveMFA() throws Exception {
		List<PestoIdPImpl> idps = new ArrayList<>();
		TestIdP idp = new TestIdP(null);
		idps.add(idp);
		CredentialManagement cManager = new PSCredentialManagement(true, new InMemoryCredentialStorage(), 60);
		PabcClient authClient = new PabcClient(idps, cManager, cCryptoModule);
		authClient.removeMFA(user, password, "none", GoogleAuthenticator.TYPE);
		fail();
	}

	private class TestIdP extends PestoIdPImpl {

		public TestIdP(List<IdentityProver> identityProvers) throws Exception {
			super(new InMemoryPestoDatabase() {
				@Override
				public boolean hasUser(String username) {
					if (username.equals(user)) {
						return true;
					}
					return false;
				}}, identityProvers, mfaAuthenticators,
					new SoftwareServerCryptoModule(new Random(1)));
		}
		
		@Override
		public String getCredentialShare(String username, byte[] cookie, long salt, byte[] signature, long timestamp) {
			assertEquals("username", username);
			Map<String, Attribute> attributes = new HashMap<String, Attribute>();
			attributes.put("name", new Attribute("John"));
			BIG x = new BIG(5);
			ZpElement zpElement = new ZpElementBLS461(x);
			Group2Element g1Element = new PairingBuilderBLS461().getGroup2Generator();
			
			PSsignature psSignature = new PSsignature(zpElement, g1Element, g1Element);
			// PSCredential credential = new PSCredential(System.currentTimeMillis(), attributes, psSignature);

			VerifiableCredential vc = W3CSerializationUtil.generateVCredential(
					new Date(),
					attributes,
					null, false, null, null, null, null, new Date(), psSignature.getEnconded(),
					"https://olympus-deployment.eu/example/context", "https://olympus-project.eu/example/validationSchema", "https://olympus-project.eu/example/encodingSchema", URI.create("did:meta:OL-vIdP"));

			return vc.toJSONString();
		}
		
		
		@Override
		public OPRFResponse performOPRF(String ssid, String username, ECP x, String mfaToken, String mfaType){
			assertEquals("username", username);
			assertNotNull(ssid);
			assertNotNull(x);
			FP12 output = sCryptoModule.hashAndPair(ssid.getBytes(), x);
			return new OPRFResponse(output, ssid, "session");
		}
	}
	
}
