package eu.olympus.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import eu.olympus.TestParameters;
import eu.olympus.model.Attribute;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.server.rest.UsernameAndPassword;
import eu.olympus.server.DistributedRSAIdP;
import eu.olympus.server.GoogleAuthenticator;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.storage.InMemoryUserPasswordDatabase;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.Test;

public class TestDistributedRSAClient {
	private final static String user = "username";
	private final static String password = "password";

	@Test(expected = AuthenticationFailedException.class)
	public void testMissingUserMFAChallenge() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<>();
		Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
		mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(0))));
		DistributedRSAIdP idp1 = new DistributedRSAIdP(new InMemoryUserPasswordDatabase(), 0, new ArrayList<>(), null, mfaAuthenticators, TestParameters.getRSA1Cert()) {
			@Override
			public String startSession(UsernameAndPassword auth, String token, String type) {
				return "cookie";
			}

			@Override
			public String requestMFA(UsernameAndPassword authentication, byte[] cookie, String type)
					throws AuthenticationFailedException {
				return "request1";
			}
		};

		DistributedRSAIdP idp2 = new DistributedRSAIdP(new InMemoryUserPasswordDatabase(), 0, new ArrayList<>(), null, mfaAuthenticators, TestParameters.getRSA1Cert()) {
			@Override
			public String startSession(UsernameAndPassword auth, String token, String type) {
				return "cookie";
			}

			@Override
			public String requestMFA(UsernameAndPassword authentication, byte[] cookie, String type)
					throws AuthenticationFailedException {
				return "request2";
			}
		};
		idps.add(idp1);
		idps.add(idp2);
		DistributedRSAClient authClient = new DistributedRSAClient(idps);
		authClient.requestMFAChallenge(user, password, GoogleAuthenticator.TYPE);
		fail();
	}
	
	@Test(expected = AuthenticationFailedException.class)
	public void testMissingConfirmMFA() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<>();

		Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
		mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(0))));
		DistributedRSAIdP idp = new DistributedRSAIdP(new InMemoryUserPasswordDatabase(), 0, new ArrayList<>(), null, mfaAuthenticators, TestParameters.getRSA1Cert()) {
			@Override
			public String startSession(UsernameAndPassword auth, String token, String type) {
				return "cookie";
			}
		};
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps);
		authClient.confirmMFA(user, password, "none", GoogleAuthenticator.TYPE);
		fail();
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testMissingRemoveMFA() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<>();

		Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
		mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(0))));
		DistributedRSAIdP idp = new DistributedRSAIdP(new InMemoryUserPasswordDatabase(), 0, new ArrayList<>(), null, mfaAuthenticators, TestParameters.getRSA1Cert()) {
			@Override
			public String startSession(UsernameAndPassword auth, String token, String type) {
				return "cookie";
			}
		};
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps);
		authClient.removeMFA(user, password, "none", GoogleAuthenticator.TYPE);
		fail();
	}

	@Test
	public void testMissingUser() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<>();

		Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
		mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(0))));
		DistributedRSAIdP idp = new DistributedRSAIdP(new InMemoryUserPasswordDatabase(), 0, new ArrayList<>(), null, mfaAuthenticators,  TestParameters.getRSA1Cert()) {
			@Override
			public String startSession(UsernameAndPassword auth, String token, String type) {
				return "cookie";
			}
		};
		idps.add(idp);
		DistributedRSAClient client = new DistributedRSAClient(idps);
		try {
			client.removeMFA("otherUser", password, "none", GoogleAuthenticator.TYPE);
			fail();
		} catch (Exception e) {
			// correct behaviour
		}
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testFailedDeleteAccount() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<>();

		Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
		mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(0))));
		DistributedRSAIdP idp = new DistributedRSAIdP(new InMemoryUserPasswordDatabase(), 0, new ArrayList<>(), null, mfaAuthenticators,  TestParameters.getRSA1Cert()) {
			@Override
			public String startSession(UsernameAndPassword auth, String token, String type) {
				if (!auth.getUsername().equals(user) || !auth.getPassword().equals(password) ) {
					return "not-cookie";
				}
				return "cookie";
			}
			@Override
			public boolean deleteAccount(UsernameAndPassword authentication, byte[] cookie){
				return authentication.equals(user) && Arrays.equals("cookie".getBytes(), cookie);
			}
		};
		idps.add(idp);
		DistributedRSAClient client = new DistributedRSAClient(idps);
		client.deleteAccount(user, "wrong-password", null,  "NONE");
		fail();
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testFailedDeleteAttributes() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<>();

		Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
		mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(0))));
		DistributedRSAIdP idp = new DistributedRSAIdP(new InMemoryUserPasswordDatabase(), 0, new ArrayList<>(), null, mfaAuthenticators,  TestParameters.getRSA1Cert() ) {
			@Override
			public String startSession(UsernameAndPassword auth, String token, String type) {
				if (!auth.getUsername().equals(user) || !auth.getPassword().equals(password) ) {
					return "not-cookie";
				}
				return "cookie";
			}
			@Override
			public boolean deleteAttribute(String username, byte[] cookie, List<String> attributes) throws AuthenticationFailedException {
				return username.equals(user) && Arrays.equals("cookie".getBytes(), cookie);
			}
		};
		idps.add(idp);
		DistributedRSAClient client = new DistributedRSAClient(idps);
		client.deleteAttributes(user, "wrong-password", Arrays.asList("name"), null,  "NONE");
		fail();
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testFailedGetAllAttributes() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<>();

		Map<String, MFAAuthenticator> mfaAuthenticators = new HashMap<>();
		mfaAuthenticators.put(GoogleAuthenticator.TYPE, new GoogleAuthenticator(new SoftwareServerCryptoModule(new Random(0))));
		DistributedRSAIdP idp = new DistributedRSAIdP(new InMemoryUserPasswordDatabase(), 0, new ArrayList<>(), null, mfaAuthenticators, TestParameters.getRSA1Cert()) {
			@Override
			public String startSession(UsernameAndPassword auth, String token, String type) {
				return "cookie";
			}
			@Override
			public Map<String, Attribute> getAllAttributes(String username, byte[] cookie) {
				Map<String, Attribute> map = new HashMap<>();
				map.put("name", new Attribute("Marge Simpson"));
				return map;
			}
		};
		DistributedRSAIdP idp2 = new DistributedRSAIdP(new InMemoryUserPasswordDatabase(), 0, new ArrayList<>(), null, mfaAuthenticators,  TestParameters.getRSA1Cert() ) {
			@Override
			public String startSession(UsernameAndPassword auth, String token, String type) {
				return "cookie";
			}
			@Override
			public Map<String, Attribute> getAllAttributes(String username, byte[] cookie) {
				Map<String, Attribute> map = new HashMap<>();
				map.put("name", new Attribute("Homer Simpson"));
				return map;
			}
		};
		idps.add(idp);
		idps.add(idp2);
		DistributedRSAClient client = new DistributedRSAClient(idps);
		client.getAllAttributes(user, "wrong-password",null,  "NONE");
		fail();
	}

	@Test
	public void testGetAllAttributesWithMFA() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		TestIdP idp = new TestIdP();
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
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
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		TestIdP idp = new TestIdP() {
			@Override
			public Map<String, Attribute> getAllAttributes(String username, byte[] cookie) {
				throw new RuntimeException("simulated server failure");
			}
		};
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
		authClient.getAllAttributes("username", "password", null, "NONE");
		fail();
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testGetAllAttributesDifferingServerOutputs() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		TestIdP idp = new TestIdP() {
			@Override
			public Map<String, Attribute> getAllAttributes(String username, byte[] cookie) {
				Map<String, Attribute> output = new HashMap<>();
				output.put("name", new Attribute("John"));
				return output;
			}
		};
		idps.add(idp);
		TestIdP idp2 = new TestIdP() {
			@Override
			public Map<String, Attribute> getAllAttributes(String username, byte[] cookie) {
				Map<String, Attribute> output = new HashMap<>();
				output.put("name", new Attribute("Bob"));
				return output;
			}
		};
		idps.add(idp2);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
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
	public void testDeleteAttributesWithMFA() throws Exception {
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		TestIdP idp = new TestIdP();
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
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
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		TestIdP idp = new TestIdP() {
			@Override
			public boolean deleteAttribute(String username, byte[] cookie, List<String> attributes) {
				throw new RuntimeException("simulated server failure");
			}
		};
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
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
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		TestIdP idp = new TestIdP() {
			@Override
			public boolean deleteAttribute(String username, byte[] cookie, List<String> attributes) {
				return false;
			}
		};
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
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
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		TestIdP idp = new TestIdP();
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
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
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		TestIdP idp = new TestIdP() {
			@Override
			public boolean deleteAccount(UsernameAndPassword authentication, byte[] cookie) {
				throw new RuntimeException("simulated server failure");
			}
		};
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
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
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		TestIdP idp = new TestIdP() {
			@Override
			public boolean deleteAccount(UsernameAndPassword authentication, byte[] cookie) {
				return false;
			}
		};
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
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
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		TestIdP idp = new TestIdP();
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
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
		List<DistributedRSAIdP> idps = new ArrayList<DistributedRSAIdP>();
		TestIdP idp = new TestIdP() {
			@Override
			public void changePassword(
					UsernameAndPassword oldAuthenticationData, String newPassword, byte[] cookie) {
				throw new RuntimeException("Planned failure");
			}
		};
		idps.add(idp);
		DistributedRSAClient authClient = new DistributedRSAClient(idps) {
			@Override
			public String authenticate(String username, String password, Policy policy, String token, String type) {
				//Not used for testing
				return null;
			}
		};
		authClient.changePassword("username", "password", "password2", null, "NONE");
		fail();
	}
	
	private class TestIdP extends DistributedRSAIdP {

		public TestIdP() throws Exception {
			super(new InMemoryUserPasswordDatabase(), 0, new ArrayList<>(), new SoftwareServerCryptoModule(new Random(1)), new HashMap<String, MFAAuthenticator>(), TestParameters.getRSA1Cert());
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
			assertEquals("username", oldAuthenticationData.getUsername());
			assertEquals("cookie", new String(cookie));
			changePWReached = true;
		}
	}

}
