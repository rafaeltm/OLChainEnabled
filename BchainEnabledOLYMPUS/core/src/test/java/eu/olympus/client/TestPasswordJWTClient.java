package eu.olympus.client;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.TestParameters;
import eu.olympus.model.Attribute;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.IdentityProof;
import eu.olympus.model.server.rest.UsernameAndPassword;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.PasswordJWTIdP;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.Storage;
import eu.olympus.server.storage.InMemoryUserPasswordDatabase;
import eu.olympus.unit.server.TestIdentityProof;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.apache.commons.codec.binary.Base64;
import org.junit.BeforeClass;
import org.junit.Test;

public class TestPasswordJWTClient {

	private final static String user = "username";
	private final static String password = "password";
	private final static String signature = "signature";
	private final static String challenge = "challenge";
	private final static Map<String, Attribute> attributes = new HashMap<>();
	private final static List<String> claims = new LinkedList<String>();
	
	static PasswordJWTIdP dummyIdP;

	static class TestPasswordJWTIdP extends PasswordJWTIdP {

		public TestPasswordJWTIdP(Storage db, HashMap<String, MFAAuthenticator> mfas ) {
			super(db, new ArrayList<>(), mfas);
		}

		ObjectMapper objectMapper = new ObjectMapper();

		@Override
		public Certificate getCertificate() {
			return null;
		}

		@Override
		public void createUser(UsernameAndPassword creationData)
					throws UserCreationFailedException {
			assertThat(creationData.getUsername(), is(user));
			assertThat(creationData.getPassword(), is(password));
		}

		@Override
		public void createUserAndAddAttributes(UsernameAndPassword creationData, IdentityProof proof)
					throws UserCreationFailedException {
			try {
				TestIdentityProof idProof = (TestIdentityProof) proof;
				assertThat(creationData.getUsername(), is(user));
				assertThat(creationData.getPassword(), is(password));
				assertThat(idProof.getSignature(), is(signature));
				assertThat(idProof.getAttributes().size(), is(2));
				for (String s : idProof.getAttributes().keySet()) {
					assertThat(idProof.getAttributes().get(s), is(attributes.get(s)));
				}
			} catch (Exception e) {
				fail(e.getMessage());
			}
		}

		@Override
		public void addAttributes(String username, byte[] cookie, IdentityProof proof)
					throws AuthenticationFailedException {
			TestIdentityProof idProof = (TestIdentityProof) proof;
			assertTrue(Arrays.equals("valid-cookie".getBytes(), cookie));
			assertThat(username, is(user));
			assertThat(idProof.getSignature(), is(signature));
			assertThat(idProof.getAttributes().size(), is(2));
			for (String s : idProof.getAttributes().keySet()) {
				assertThat(idProof.getAttributes().get(s), is(attributes.get(s)));
			}
		}

		@Override
		public String authenticate(String username, byte[] cookie, Policy policy) {
			if (!username.equals(user) || !Arrays.equals("valid-cookie".getBytes(), cookie)) {
				return null;
			}
			for (Predicate p : policy.getPredicates()) {
				assertThat(claims, hasItem(p.getAttributeName()));
			}
			assertEquals(policy.getPredicates().size(), claims.size());
			return "Dummy-Authenticate";
		}

		@Override
		public String startSession(UsernameAndPassword auth, String token, String type) {
			if (!auth.getUsername().equals(user) || !auth.getPassword().equals(password)) {
				return Base64.encodeBase64String("invalid-cookie".getBytes());
			}
			return Base64.encodeBase64String("valid-cookie".getBytes());
		}

		@Override
		public boolean deleteAccount(UsernameAndPassword authentication, byte[] cookie) throws AuthenticationFailedException {
			return Arrays.equals("valid-cookie".getBytes(), cookie);
		}

		@Override
		public boolean deleteAttribute(String username, byte[] cookie, List<String> attributes)
				throws AuthenticationFailedException {
			return Arrays.equals("valid-cookie".getBytes(), cookie);
		}

		@Override
		public String requestMFA(UsernameAndPassword authentication, byte[] cookie, String type)
				throws AuthenticationFailedException {
			assertThat(authentication.getUsername(), is(user));
			assertThat(authentication.getPassword(), is(password));
			return challenge;
		}
	}

	static class TestInMemoryStorage extends InMemoryUserPasswordDatabase {
		@Override
		public boolean hasUser(String username) {
			return username.equals(user);
		}

		@Override
		public String getSalt(String username) {
			return "salt";
		}

		@Override
		public String getPassword(String username) {
			if (username.equals(username)) {
				return "h50rZTkC3PWiu4hjyvowdht3BzuR4EkTW4dbfYSABVbJ7vLVZwlO8Mihj4HqLTOxoo15aWkOPRVCpASig0qRcw=="; // hashed password
			}
			return null;
		}
	}

	@BeforeClass
	public static void setup(){
		claims.add("name");
		claims.add("age");
		attributes.put("name", new Attribute("John"));
		attributes.put("age", new Attribute(22));
		HashMap<String, MFAAuthenticator> mfas = new HashMap<>();
		mfas.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(1))));
		dummyIdP = new TestPasswordJWTIdP(new TestInMemoryStorage() ,mfas);
	}
	

	@Test
	public void testCreateUser() throws UserCreationFailedException {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);
		client.createUser(user, password);
	}

	
	@Test
	public void testCreateUserAndAddAtrtibutes() throws UserCreationFailedException {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);
		client.createUserAndAddAttributes(user, password, new TestIdentityProof(signature, attributes));
	}
	
	@Test
	public void testAddAttributes() throws AuthenticationFailedException {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);
		client.addAttributes(user, password, new TestIdentityProof(signature, attributes), null, "NONE");
	}
	
	@Test
	public void testAuthenticate() throws UserCreationFailedException, AuthenticationFailedException {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);
		Policy policy = new Policy();
		List<Predicate> predicates = new ArrayList<>();
		for(String s: claims) {
			Predicate predicate = new Predicate();
			predicate.setAttributeName(s);
			predicate.setOperation(Operation.REVEAL);
			predicates.add(predicate);
		}
		policy.setPredicates(predicates);
		String reply = client.authenticate(user, password, policy, null, "NONE");
		assertThat(reply, is("Dummy-Authenticate"));
	}
	
	@Test
	public void testRequestMFAChallenge() throws Exception {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);
		String challenge = client.requestMFAChallenge(user, password, GoogleAuthenticator.TYPE);
		assertEquals(challenge, TestPasswordJWTClient.challenge);
	}
	
	@Test(expected = AuthenticationFailedException.class)
	public void testMissingConfirmMFA() throws Exception {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);

		client.confirmMFA(user, password, "none", GoogleAuthenticator.TYPE);
		fail();
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testMissingRemoveMFA() throws Exception {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);

		client.removeMFA(user, password, "none", GoogleAuthenticator.TYPE);
		fail();
	}

	@Test
	public void testMissingUser() {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);
		try {
			client.removeMFA("otherUser", password, "none", GoogleAuthenticator.TYPE);
			fail();
		} catch (Exception e) {
			// correct behaviour
		}
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testFailedAuthentication() throws Exception {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);

		client.authenticate(user, "wrong-password", new Policy(), null, "NONE");
		fail();
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testFailedDeleteAttributes() throws Exception {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);
		client.deleteAttributes(user, "wrong-password", Arrays.asList("name"), null, "NONE");
		fail();
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testFailedDeleteAccount() throws Exception {
		List<PasswordJWTIdP> servers = new LinkedList<>();
		servers.add(dummyIdP);
		PasswordJWTClient client = new PasswordJWTClient(servers);
		client.deleteAccount(user, "wrong-password", null, "NONE");
		fail();
	}
	
	@Test
	public void testGetAllAttributes() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PasswordJWTClient authClient = new PasswordJWTClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
		idp.createUser(new UsernameAndPassword("username", "password"));
		Map<String, Attribute> attributes = authClient.getAllAttributes("username", "password", null, "NONE");
		assertEquals(2, attributes.size());
		assertEquals(new Attribute("John"), attributes.get("name"));
		assertEquals(new Attribute("John2"), attributes.get("name2"));
	}

	@Test
	public void testGetAllAttributesWithMFA() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PasswordJWTClient authClient = new PasswordJWTClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
		idp.createUser(new UsernameAndPassword("username", "password"));
		Map<String, Attribute> attributes = authClient.getAllAttributes("username", "password", "TOKEN", GoogleAuthenticator.TYPE);
		assertEquals(2, attributes.size());
		assertEquals(new Attribute("John"), attributes.get("name"));
		assertEquals(new Attribute("John2"), attributes.get("name2"));
	}
	
	@Test(expected = AuthenticationFailedException.class)
	public void testGetAllAttributesServerFailure() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		TestIdP idp = new TestIdP() {
			@Override
			public Map<String, Attribute> getAllAttributes(String username, byte[] cookie) {
				throw new RuntimeException("simulated server failure");
			}
		};
		idps.add(idp);
		PasswordJWTClient authClient = new PasswordJWTClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
		authClient.getAllAttributes("username", "password", null, "NONE");
		fail();
	}

	@Test
	public void testDeleteAttributes() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PasswordJWTClient authClient = new PasswordJWTClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
		idp.createUser(new UsernameAndPassword("username", "password"));
		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes("username", "password", toDelete, null, "NONE");
		assertTrue(idp.deleteAttributeReached);
	}

	@Test
	public void testDeleteAttributesWithMFA() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PasswordJWTClient authClient = new PasswordJWTClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
		idp.createUser(new UsernameAndPassword("username", "password"));
		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes("username", "password", toDelete, "TOKEN", GoogleAuthenticator.TYPE);
		assertTrue(idp.deleteAttributeReached);
	}
	
	@Test(expected = AuthenticationFailedException.class)
	public void testDeleteAttributesServerFailure() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		TestIdP idp = new TestIdP() {
			@Override
			public boolean deleteAttribute(String username, byte[] cookie, List<String> attributes) {
				throw new RuntimeException("simulated server failure");
			}
		};
		idps.add(idp);
		PasswordJWTClient authClient = new PasswordJWTClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes("username", "password", toDelete, null, "NONE");
		fail();
	}
	
	@Test(expected = AuthenticationFailedException.class)
	public void testDeleteAttributesServerNegativeAnswer() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		TestIdP idp = new TestIdP() {
			@Override
			public boolean deleteAttribute(String username, byte[] cookie, List<String> attributes) {
				return false;
			}
		};
		idps.add(idp);
		PasswordJWTClient authClient = new PasswordJWTClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};

		List<String> toDelete = new ArrayList<String>();
		toDelete.add("John");
		authClient.deleteAttributes("username", "password", toDelete, null, "NONE");
		fail();
	}
	
	@Test
	public void testDeleteAccountWithMFA() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PasswordJWTClient authClient = new PasswordJWTClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};

		idp.createUser(new UsernameAndPassword("username", "password"));
		authClient.deleteAccount("username", "password", "TOKEN", GoogleAuthenticator.TYPE);
		assertTrue(idp.deleteAccountReached);
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testDeleteAccountServerFailure() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		TestIdP idp = new TestIdP() {
			@Override
			public boolean deleteAccount(UsernameAndPassword authentication, byte[] cookie) {
				throw new RuntimeException("simulated server failure");
			}
		};
		idps.add(idp);
		PasswordJWTClient authClient = new PasswordJWTClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};

		authClient.deleteAccount("username", "password", null, "NONE");
		fail();
	}
	
	@Test(expected = AuthenticationFailedException.class)
	public void testDeleteAccountServerFailureNice() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		TestIdP idp = new TestIdP() {
			@Override
			public boolean deleteAccount(UsernameAndPassword authentication, byte[] cookie) {
				return false;
			}
		};
		idps.add(idp);
		PasswordJWTClient authClient = new PasswordJWTClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};

		authClient.deleteAccount("username", "password", null, "NONE");
		fail();
	}
	
	@Test
	public void testChangePasswordWithMFA() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		TestIdP idp = new TestIdP();
		idps.add(idp);
		PasswordJWTClient authClient = new PasswordJWTClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
		idp.createUser(new UsernameAndPassword("username", "password"));
		authClient.changePassword("username", "password", "password2", "TOKEN", GoogleAuthenticator.TYPE);
		assertTrue(idp.changePWReached);
	}
	
	@Test(expected=AuthenticationFailedException.class)
	public void testChangePasswordBadServerSignature() throws Exception {
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		TestIdP idp = new TestIdP() {
			@Override
			public void changePassword(
					UsernameAndPassword oldAuthenticationData, String newPassword, byte[] cookie) {
				throw new RuntimeException("planned failure");
			}
		};
		idps.add(idp);
		PasswordJWTClient authClient = new PasswordJWTClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
		authClient.changePassword("username", "password", "password2", null, "NONE");
		fail();
	}
	
	private class TestIdP extends PasswordJWTIdP {

		public TestIdP() throws Exception {
			super(new InMemoryUserPasswordDatabase(), new ArrayList<>(), new HashMap<String, MFAAuthenticator>());
		}
		
		@Override
		public String startSession(UsernameAndPassword authentication, String token, String type)
				throws AuthenticationFailedException {
			if("NONE".equals(type)) {
				return "Y29va2ll";
			}
			assertEquals("TOKEN", token);
			assertEquals(GoogleAuthenticator.TYPE, type);
			return "Y29va2ll";
		}
		
		@Override
		public Certificate getCertificate() {
			return TestParameters.getRSA1Cert();
		}
	
		@Override
		public Map<String, Attribute> getAllAttributes(String username, byte[] cookie) {
			assertEquals("username", username);
			assertEquals("cookie", new String(cookie));
			
			Map<String, Attribute> attributes = new HashMap<String, Attribute>();
			attributes.put("name", new Attribute("John"));
			attributes.put("name2", new Attribute("John2"));
			return attributes;
		}
		
		public boolean deleteAttributeReached = false;
		@Override
		public boolean deleteAttribute(String username, byte[] cookie, List<String> attributes) {
			assertEquals("username", username);
			assertEquals("cookie", new String(cookie));
			assertEquals(1, attributes.size());
			assertEquals("John", attributes.get(0));
			deleteAttributeReached = true;
			return true;
		}
		
		public boolean deleteAccountReached = false;
		@Override
		public boolean deleteAccount(UsernameAndPassword authentication, byte[] cookie) {
			assertEquals("username", authentication.getUsername());
			assertEquals("password", authentication.getPassword());
			assertEquals("cookie", new String(cookie));
			deleteAccountReached = true;
			return true;
		}
		
		public boolean changePWReached = false;

		@Override
		public void changePassword(
				UsernameAndPassword oldAuthenticationData, String newPassword, byte[] cookie) {
			assertEquals("cookie", new String(cookie));
			assertEquals("username", oldAuthenticationData.getUsername());
			assertEquals("password2", newPassword);
			changePWReached = true;
		}
	}
}
