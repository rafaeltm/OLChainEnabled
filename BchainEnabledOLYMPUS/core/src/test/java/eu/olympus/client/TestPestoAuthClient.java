package eu.olympus.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.TestParameters;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.model.Attribute;
import eu.olympus.model.KeyShares;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.Policy;
import eu.olympus.model.RSASharedKey;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.rest.CommonRESTEndpoints;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import eu.olympus.unit.server.TestIdentityProof;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.apache.commons.codec.Charsets;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.FP12;


public class TestPestoAuthClient {
	@Rule
	public final ExpectedException exception = ExpectedException.none();
	
	private ServerCryptoModule sCryptoModule = new SoftwareServerCryptoModule(new Random(1));
	private SoftwareClientCryptoModule cCryptoModule = null;
	private List<PestoIdPImpl> idps;
	
	@Before
	public void setupCrypto() throws Exception{
		RSAPrivateKey pk = TestParameters.getRSAPrivateKey2();
		BigInteger d = pk.getPrivateExponent();
		RSASharedKey keyMaterial = new RSASharedKey(pk.getModulus(), d, TestParameters.getRSAPublicKey2().getPublicExponent());
		Map<Integer, BigInteger> rsaBlindings = new HashMap<>();
		BigInteger oprfKey = new BigInteger("42");
		sCryptoModule.setupServer(new KeyShares(keyMaterial, rsaBlindings, oprfKey, null));
		cCryptoModule = new SoftwareClientCryptoModule(new Random(1), pk.getModulus());
		idps = new ArrayList<PestoIdPImpl>();
	}
	
	@Test
	public void testCreateUserAndAddAttributes() throws Exception {
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule) {
		};
		
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put("name", new Attribute("John"));
		TestIdentityProof idProof = new TestIdentityProof("sig", attributes);
		authClient.createUserAndAddAttributes("username", "password", idProof);
	}
	
	@Test
	public void testCreateUserWithoutID() throws Exception {
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username", "password");
	}
	
	@Test(expected=UserCreationFailedException.class)
	public void testCreateUserBadServerSignature() throws Exception {
		TestIdP idp = new TestIdP() {
			@Override
			public byte[] finishRegistration(String username, byte[] cookie, PublicKey publicKey, byte[] signature, long salt, String idProof) {
				assertEquals("username", username);
				List<byte[]> input = new ArrayList<>();
				input.add(sCryptoModule.constructNonce(username, salt));
				input.add(username.getBytes());
				try {
					assertTrue(sCryptoModule.verifySignature(publicKey, input, signature));
				} catch (Exception e) {
					fail();
				}
				try {
					byte[] serverSignature = new byte[256];
					new Random(1).nextBytes(serverSignature);
					return serverSignature;
				} catch(Exception e) {
					fail();
				}
				return null;
			}
		};
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.createUser("username", "password");
		fail();
	}
	
	@Test(expected=UserCreationFailedException.class)
	public void testCreateUserAndAddAttributesBadServerSignature() throws Exception {
		TestIdP idp = new TestIdP() {
			@Override
			public byte[] finishRegistration(String username, byte[] cookie, PublicKey publicKey, byte[] signature, long salt, String idProof) {
				assertEquals("username", username);
				List<byte[]> input = new ArrayList<>();
				input.add(sCryptoModule.constructNonce(username, salt));
				input.add(username.getBytes());
				if (idProof == null) {
					idProof = "";
				}
				input.add((CommonRESTEndpoints.CREATE_USER_AND_ADD_ATTRIBUTES+idProof).getBytes(Charsets.UTF_8));
				try {
					assertTrue(sCryptoModule.verifySignature(publicKey, input, signature));
				} catch (Exception e) {
					fail();
				}
				try {
					byte[] serverSignature = new byte[384];
					new Random(1).nextBytes(serverSignature);
					return serverSignature;
				} catch(Exception e) {
					fail();
				}
				return null;
			}
		};
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put("name", new Attribute("John"));
		TestIdentityProof idProof = new TestIdentityProof("sig", attributes);
		authClient.createUserAndAddAttributes("username", "password", idProof);
		fail();
	}
	
	
	@Test(expected=UserCreationFailedException.class)
	public void testCreateUserAndAddAttributes1BadServerSignature() throws Exception {
		TestIdP idp = new TestIdP() {
			@Override
			public byte[] finishRegistration(String username, byte[] cookie, PublicKey publicKey, byte[] signature, long salt, String idProof) {
				assertEquals("username", username);
				List<byte[]> input = new ArrayList<>();
				input.add(sCryptoModule.constructNonce(username, salt));
				input.add(username.getBytes());
				if (idProof == null) {
					idProof = "";
				}
				input.add((CommonRESTEndpoints.CREATE_USER_AND_ADD_ATTRIBUTES+idProof).getBytes(Charsets.UTF_8));
				try {
					byte[] serverSignature = new byte[384];
					new Random(1).nextBytes(serverSignature);
					return serverSignature;
				} catch(Exception e) {
					fail();
				}
				return null;
			}
		};
		idps.add(idp);
		TestIdP idp2 = new TestIdP();
		idps.add(idp2);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put("name", new Attribute("John"));
		TestIdentityProof idProof = new TestIdentityProof("sig", attributes);
		authClient.createUserAndAddAttributes("username", "password", idProof);
		fail();
	}
	
	@Test
	public void testAddAttributes() throws Exception {
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put("name", new Attribute("John"));
		TestIdentityProof idProof = new TestIdentityProof("sig", attributes);
		authClient.addAttributes("username", "password", idProof, null, "NONE");
	}

	@Test
	public void testAddAttributesWithMFA() throws Exception {
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put("name", new Attribute("John"));
		TestIdentityProof idProof = new TestIdentityProof("sig", attributes);
		authClient.addAttributes("username", "password", idProof, "TOKEN", GoogleAuthenticator.TYPE);
	}
	
	@Test(expected=AuthenticationFailedException.class)
	public void testAddAttributesServerFails() throws Exception {
		TestIdP idp = new TestIdP() {
			@Override
			public boolean addAttributes(String username, byte[] cookie, long salt, byte[] signature, String idProof) {
				throw new RuntimeException("simulated server failure");
			}
		};
		
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put("name", new Attribute("John"));
		TestIdentityProof idProof = new TestIdentityProof("sig", attributes);
		authClient.addAttributes("username", "password", idProof, null, "NONE");
		fail();
	}
	
	@Test
	public void testAddAttributesServerNegativeAnswer() throws Exception {
		TestIdP idp = new TestIdP() {
			@Override
			public boolean addAttributes(String username, byte[] cookie, long salt, byte[] signature, String idProof) {
				return false;
			}
		};

		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put("name", new Attribute("John"));
		TestIdentityProof idProof = new TestIdentityProof("sig", attributes);
		try {
			authClient.addAttributes("username", "password", idProof, null, "NONE");
			fail();
		}catch(AuthenticationFailedException e) {
			return;
		}
		fail();
	}
	
	@Test
	public void testGetAllAttributes() throws Exception {
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		Map<String, Attribute> attributes = authClient.getAllAttributes("username", "password", null, "NONE");
		assertEquals(2, attributes.size());
		assertEquals(new Attribute("John"), attributes.get("name"));
		assertEquals(new Attribute("John2"), attributes.get("name2"));
	}

	@Test
	public void testGetAllAttributesWithMFA() throws Exception {
		List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		Map<String, Attribute> attributes = authClient.getAllAttributes("username", "password", "TOKEN", GoogleAuthenticator.TYPE);
		assertEquals(2, attributes.size());
		assertEquals(new Attribute("John"), attributes.get("name"));
		assertEquals(new Attribute("John2"), attributes.get("name2"));
	}
	
	@Test(expected = AuthenticationFailedException.class)
	public void testGetAllAttributesServerFailure() throws Exception {
		TestIdP idp = new TestIdP() {
			@Override
			public Map<String, Attribute> getAllAttributes(String username, byte[] cookie, long salt, byte[] signature) {
				throw new RuntimeException("simulated server failure");
			}
		};
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.getAllAttributes("username", "password", null, "NONE");
		fail();
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testGetAllAttributesDifferingServerOutputs() throws Exception {
		TestIdP idp = new TestIdP() {
			@Override
			public Map<String, Attribute> getAllAttributes(String username, byte[] cookie, long salt, byte[] signature) {
				Map<String, Attribute> output = new HashMap<>();
				output.put("name", new Attribute("John"));
				return output;
			}
		};
		idps.add(idp);
		TestIdP idp2 = new TestIdP() {
			@Override
			public Map<String, Attribute> getAllAttributes(String username, byte[] cookie, long salt, byte[] signature) {
				Map<String, Attribute> output = new HashMap<>();
				output.put("name", new Attribute("Bob"));
				return output;
			}
		};
		idps.add(idp2);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.getAllAttributes("username", "password", null, "NONE");
		fail();
	}

	
	@Test
	public void testDeleteAttributes() throws Exception {
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes("username", "password", toDelete, null, "NONE");
	}

	@Test
	public void testDeleteAttributesWithMFA() throws Exception {
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes("username", "password", toDelete, "TOKEN", GoogleAuthenticator.TYPE);
	}
	
	@Test(expected = AuthenticationFailedException.class)
	public void testDeleteAttributesServerFailure() throws Exception {
		TestIdP idp = new TestIdP() {
			@Override
			public boolean deleteAttributes(String username, byte[] cookie, long salt, byte[] signature, List<String> attributes) {
				throw new RuntimeException("simulated server failure");
			}
		};
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes("username", "password", toDelete, null, "NONE");
		fail();
	}
	
	@Test(expected = AuthenticationFailedException.class)
	public void testDeleteAttributesServerNegativeAnswer() throws Exception {
		TestIdP idp = new TestIdP() {
			@Override
			public boolean deleteAttributes(String username, byte[] cookie, long salt, byte[] signature, List<String> attributes) {
				return false;
			}
		};
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes("username", "password", toDelete, null, "NONE");
		fail();
	}
	
	@Test
	public void testDeleteAccount() throws Exception {
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.deleteAccount("username", "password", null, "NONE");
	}
	
	@Test
	public void testDeleteAccountWithMFA() throws Exception {
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.deleteAccount("username", "password", "TOKEN", GoogleAuthenticator.TYPE);
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testDeleteAccountServerFailure() throws Exception {
		TestIdP idp = new TestIdP() {
			@Override
			public boolean deleteAccount(String username, byte[] cookie, long salt, byte[] signature) {
				throw new RuntimeException("simulated server failure");
			}
		};
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.deleteAccount("username", "password", null, "NONE");
		fail();
	}
	
	@Test(expected = AuthenticationFailedException.class)
	public void testDeleteAccountServerFailureNice() throws Exception {
		TestIdP idp = new TestIdP() {
			@Override
			public boolean deleteAccount(String username, byte[] cookie, long salt, byte[] signature) {
				return false;
			}
		};
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.deleteAccount("username", "password", null, "NONE");
		fail();
	}
	
	@Test
	public void testChangePassword() throws Exception {
		List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.changePassword("username", "password", "password2", null, "NONE");
	}
	
	@Test
	public void testChangePasswordWithMFA() throws Exception {
//		shuld be tested that the server accepts
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.changePassword("username", "password", "password2", "session", GoogleAuthenticator.TYPE);
	}
	
	@Test(expected=AuthenticationFailedException.class)
	public void testChangePasswordBadServerSignature() throws Exception {
		TestIdP idp = new TestIdP() {
			@Override
			public byte[] changePassword(String username, byte[] cookie, PublicKey key, byte[] signature, byte[] newSignature, long salt) {
				return new byte[256];
			}
		};
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.changePassword("username", "password", "password2", null, "NONE");
		fail();
	}
	
	@Test(expected=AuthenticationFailedException.class)
	public void testOPRFBadServerSSID() throws Exception {
		TestIdP idp = new TestIdP() {
			@Override
			public OPRFResponse performOPRF(String ssid, String username, ECP x, String mfaToken, String type) {
				return new OPRFResponse(null, "ssid", "session");
			}
		};
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.changePassword("username", "password", "password2", null, "NONE");
		fail();
	}

	@Test(expected=AuthenticationFailedException.class)
	public void testRequestMFAChallengeBadResponses() throws Exception {
		TestIdP idp = new TestIdP() {
			@Override
			public String requestMFA(String username, byte[] cookie, long salt, String type, byte[] signature) {
				return "request1";
			}
		};
		idps.add(idp);
		TestIdP idp2 = new TestIdP() {
			@Override
			public String requestMFA(String username, byte[] cookie, long salt, String type, byte[] signature) {
				return "request2";
			}
		};
		idps.add(idp2);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.requestMFAChallenge("username", "password", "NONE");
		fail();
	}
	
	@Test(expected=AuthenticationFailedException.class)
	public void testConfirmMFABadServerAuth() throws Exception {
		TestIdP idp = new TestIdP() {
			@Override
			public boolean confirmMFA(String username, byte[] cookie, long salt, String token, String type, byte[] signature) {
				return false;
			}
		};
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);

		authClient.confirmMFA("username", "password", "token", "NONE");
		fail();
	}

	@Test(expected=AuthenticationFailedException.class)
	public void testRemoveMFABadServerAuth() throws Exception {
		TestIdP idp = new TestIdP() {
			@Override
			public boolean removeMFA(String username, byte[] cookie, long salt, String token, String type, byte[] signature) {
				return false;
			}
		};
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.removeMFA("username", "password", "token", "NONE");
		fail();
	}

	@Test(expected=AuthenticationFailedException.class)
	public void testRemoveMFAServerError() throws Exception {
		TestIdP idp = new TestIdP() {
			@Override
			public OPRFResponse performOPRF(String ssid, String username, ECP x, String mfaToken, String mfaType){
				throw new RuntimeException();
			}
		};
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		authClient.removeMFA("username", "password", "token", "NONE");
		fail();
	}

	@Test
	public void testFreshSaltWait() throws Exception {
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		long firstSalt = authClient.getFreshSalt();
		long secondSalt = authClient.getFreshSalt();
		assertFalse(firstSalt == secondSalt);
	}

	@Test
	public void testFreshSaltNoWait() throws Exception {
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PestoAuthClient authClient = new ConcreteAuthClient(idps, cCryptoModule);
		long firstSalt = authClient.getFreshSalt();
		Thread.sleep(2);
		long secondSalt = authClient.getFreshSalt();
		assertFalse(firstSalt == secondSalt);
	}

	private class ConcreteAuthClient extends PestoAuthClient {

		public ConcreteAuthClient(List<? extends PestoIdP> servers,
				ClientCryptoModule cryptoModule) {
			super(servers, cryptoModule);
		}

		@Override
		public String authenticate(String username, String password, Policy policy, String token, String type) {
			//Not used for testing
			return null;
		}
	}
	
	private class TestIdP extends PestoIdPImpl {

		public TestIdP() throws Exception {
			super(new InMemoryPestoDatabase(), new ArrayList<>(), new HashMap<String, MFAAuthenticator>(), new SoftwareServerCryptoModule(new Random(1)));
		}
		
		@Override
		public boolean addAttributes(String username, byte[] cookie, long salt, byte[] signature, String idProof) {
			assertEquals("username", username);
			
			ObjectMapper mapper = new ObjectMapper();
			TestIdentityProof proof;
			try {
				proof = mapper.readValue(idProof, TestIdentityProof.class);
				assertEquals("sig", proof.getSignature());
				assertEquals(new Attribute("John"),proof.getAttributes().get("name"));
				assertEquals(1, proof.getAttributes().size());
				return true;
			} catch (Exception e) {
				fail();
			}
			return false;
		}
		
		@Override
		public OPRFResponse performOPRF(String ssid, String username, ECP x, String mfaToken, String mfaType){
			assertEquals("username", username);
			assertNotNull(ssid);
			assertNotNull(x);
			FP12 output = sCryptoModule.hashAndPair(ssid.getBytes(), x);
			return new OPRFResponse(output, ssid, "aaY=");
		}
		
		@Override
		public byte[] finishRegistration(String username, byte[] cookie, PublicKey publicKey, byte[] signature, long salt, String idProof) {
			assertEquals("username", username);
			List<byte[]> input = new ArrayList<>();
			input.add(sCryptoModule.constructNonce(username, salt));
			input.add(username.getBytes());
			if(idProof != null) {
				input.add((CommonRESTEndpoints.CREATE_USER_AND_ADD_ATTRIBUTES+idProof).getBytes(Charsets.UTF_8));
			} else {
				input.add((CommonRESTEndpoints.CREATE_USER+"").getBytes(Charsets.UTF_8));
			}
			input.add(cookie);
			try {
				assertTrue(sCryptoModule.verifySignature(publicKey, input, signature));
			} catch (Exception e) {
				fail();
			}
			try {
				byte[] serverSignature = sCryptoModule.sign(publicKey, sCryptoModule.constructNonce(username, salt), 0);
				return serverSignature;
			} catch(Exception e) {
				fail();
			}
			return null;
		}
		
		@Override
		public Map<String, Attribute> getAllAttributes(String username, byte[] cookie, long salt, byte[] signature) {
			assertEquals("username", username);
			
			Map<String, Attribute> attributes = new HashMap<String, Attribute>();
			attributes.put("name", new Attribute("John"));
			attributes.put("name2", new Attribute("John2"));
			return attributes;
		}
		
		@Override
		public boolean deleteAttributes(String username, byte[] cookie, long salt, byte[] signature, List<String> attributes) {
			assertEquals("username", username);
			assertEquals(1, attributes.size());
			assertEquals("John", attributes.get(0));
			return true;
		}
		
		@Override
		public boolean deleteAccount(String username, byte[] cookie, long salt, byte[] signature) {
			assertEquals("username", username);
			return true;
		}
		
		@Override
		public byte[] changePassword(String username, byte[] cookie, PublicKey newKey, byte[] signature, byte[] newSignature, long salt) {
			assertEquals("username", username);
			try {
				byte[] serverSignature = sCryptoModule.sign(newKey, sCryptoModule.constructNonce(username, salt), 0);
				return serverSignature;
			} catch(Exception e) {
			}
			return null;
		}
	}
	
}
