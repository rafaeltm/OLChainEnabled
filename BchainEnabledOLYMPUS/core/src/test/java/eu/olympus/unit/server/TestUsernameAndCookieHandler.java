package eu.olympus.unit.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.PublicKey;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import java.util.Locale;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.ECP2;
import org.miracl.core.BLS12461.FP12;

import eu.olympus.model.Attribute;
import eu.olympus.model.Authorization;
import eu.olympus.model.KeyShares;
import eu.olympus.model.MFAInformation;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.server.AuthenticationHandler;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.interfaces.Storage;
import eu.olympus.server.interfaces.UserAuthorizationDatabase;
import eu.olympus.server.storage.InMemoryKeyDB;

public class TestUsernameAndCookieHandler {
	@Rule
	public final ExpectedException exception = ExpectedException.none();

	@Test
	public void testAddAttributes() throws Exception {
		Storage db = new TestDb() {
			@Override
			public boolean hasUser(String username) {
				return true;
			}
		};
		
		TestIP idProver = new TestIP() {
			int calls = 0;
			@Override
			public boolean isValid(String idProof, String username) {
				calls++;
				return "idProof".equals(idProof);
			}

			@Override
			public void addAttributes(String proof, String username) {
				assertEquals("idProof", proof);
				assertEquals("username", username);
				if(calls>0) {
					allCalled = true;
				}
			}
		};
		
		AuthenticationHandler authHandler = new AuthenticationHandler(db, new InMemoryKeyDB(), new HashMap<>(), null) {

			@Override
			public String requestMFASecret(String username, String type) throws Exception {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public String generateSessionCookie(String username) {
				// TODO Auto-genermated method stub
				return null;
			}
		};
		authHandler.addIdentityProver(idProver);
		authHandler.addAttributes("username", "idProof");
		assertTrue(idProver.hasBeenCalled());
	}
	
	@Test(expected = UserCreationFailedException.class)
	public void testAddAttributesNoUser() throws Exception {
		Storage db = new TestDb() {
			@Override
			public boolean hasUser(String username) {
				return false;
			}
		};
		
		AuthenticationHandler authHandler = new AuthenticationHandler(db, null, new HashMap<>(), null ) {

			@Override
			public String requestMFASecret(String username, String type) throws Exception {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public String generateSessionCookie(String username) {
				// TODO Auto-generated method stub
				return null;
			}
			
		};
		
		authHandler.addAttributes("username", "idProof");
		fail();
	}
	
	@Test(expected = UserCreationFailedException.class)
	public void testAddBadIdentityProver() throws Exception {
		Storage db = new TestDb() {
			@Override
			public boolean hasUser(String username) {
				return true;
			}
		};
		
		IdentityProver idProver = new IdentityProver() {

			@Override
			public boolean isValid(String idProof, String username) {
				return false;
			}

			@Override
			public void addAttributes(String proof, String username) {
			}
		};
		
		AuthenticationHandler authHandler = new AuthenticationHandler(db, null, new HashMap<>(), null ) {

			@Override
			public String requestMFASecret(String username, String type) throws Exception {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public String generateSessionCookie(String username) {
				// TODO Auto-generated method stub
				return null;
			}
			
		};
		authHandler.addIdentityProver(idProver);
		authHandler.addAttributes("username", "idProof");
	}
	
	@Test(expected = UserCreationFailedException.class)
	public void testAddBadIdentityProof() throws Exception {
		Storage db = new TestDb() {
			@Override
			public boolean hasUser(String username) {
				return true;
			}
		};
		
		IdentityProver idProver = new IdentityProver() {
			@Override
			public boolean isValid(String idProof, String username) {
				return false;
			}

			@Override
			public void addAttributes(String proof, String username) {
			}
		};
		
		AuthenticationHandler authHandler = new AuthenticationHandler(db, null, new HashMap<>(), null ) {

			@Override
			public String requestMFASecret(String username, String type) throws Exception {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public String generateSessionCookie(String username) {
				// TODO Auto-generated method stub
				return null;
			}
			
		};
		authHandler.addIdentityProver(idProver);
		authHandler.addAttributes("username", "idProof");
	}

	@Test
	public void testDeleteAccount() {
		TestDb db = new TestDb() {
			@Override
			public boolean deleteUser(String username) {
				allCalled = "username".equals(username);
				return true;
			}
		};
		
		AuthenticationHandler authHandler = new AuthenticationHandler(db, null, new HashMap<>(), null ) {

			@Override
			public String requestMFASecret(String username, String type) throws Exception {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public String generateSessionCookie(String username) {
				// TODO Auto-generated method stub
				return null;
			}
			
		};
		authHandler.deleteAccount("username");
		assertTrue(db.hasBeenCalled());
	}
	
	@Test
	public void testDeleteAttributes() {
		TestDb db = new TestDb() {
			@Override
			public boolean deleteAttribute(String username, String attribute) {
				allCalled = "username".equals(username);
				allCalled = allCalled && "attribute".equals(attribute);
				return true;
			}
		};
		
		AuthenticationHandler authHandler = new AuthenticationHandler(db, null, new HashMap<>(), null ) {

			@Override
			public String requestMFASecret(String username, String type) throws Exception {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public String generateSessionCookie(String username) {
				// TODO Auto-generated method stub
				return null;
			}
			
		};
		List<String> attributes = new ArrayList<String>(1);
		attributes.add("attribute");
		authHandler.deleteAttributes("username", attributes);
		assertTrue(db.hasBeenCalled());
	}
	
	@Test
	public void testGetAllAttributes() {
		TestDb db = new TestDb() {
			@Override
			public Map<String, Attribute> getAttributes(String username) {
				assertEquals("username", username);
				Map<String, Attribute> map = new HashMap<String, Attribute>();
				map.put("attribute1", new Attribute("value1"));
				map.put("attribute2", new Attribute("value2"));
				return map;
			}
		};
		
		AuthenticationHandler authHandler = new AuthenticationHandler(db, null, new HashMap<>(), null ) {

			@Override
			public String requestMFASecret(String username, String type) throws Exception {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public String generateSessionCookie(String username) {
				// TODO Auto-generated method stub
				return null;
			}
			
		};
		Map<String, Attribute> attributes = authHandler.getAllAssertions("username");
		assertEquals(2, attributes.size());
		assertEquals(new Attribute("value1"), attributes.get("attribute1"));
		assertEquals(new Attribute("value2"), attributes.get("attribute2"));
	}
	
	
	@Test
	public void testValidateAssertionsEQ() throws Exception {
		TestDb db = new TestDb();
		
		AuthenticationHandler authHandler = new AuthenticationHandler(db, null, new HashMap<>(), null ) {

			@Override
			public String requestMFASecret(String username, String type) throws Exception {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public String generateSessionCookie(String username) {
				// TODO Auto-generated method stub
				return null;
			}
			
		};
		Policy policy = new Policy();
		List<Predicate> predicates = new LinkedList<>();
		Predicate predicate = new Predicate("attribute1", Operation.EQ, new Attribute("13"));
		predicates.add(predicate);
		predicate = new Predicate("attribute2", Operation.EQ, new Attribute(15));
		predicates.add(predicate);
		predicate = new Predicate("attribute3", Operation.EQ, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("1.1.1980")));
		predicates.add(predicate);
		policy.setPredicates(predicates);

		Map<String, Attribute> response = authHandler.validateAssertions("username", policy);
		assertEquals(3, response.size());
		assertEquals(new Attribute(true), response.get("attribute1EQUALS13"));
		assertEquals(new Attribute(true), response.get("attribute2EQUALS15"));
		assertEquals(new Attribute(true), response.get("attribute3EQUALS01.01.80"));
	}
	
	@Test
	public void testValidateAssertionsBadEQ() throws Exception {
		TestDb db = new TestDb();
		
		AuthenticationHandler authHandler = new AuthenticationHandler(db, null, new HashMap<>(), null ) {

			@Override
			public String requestMFASecret(String username, String type) throws Exception {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public String generateSessionCookie(String username) {
				// TODO Auto-generated method stub
				return null;
			}
			
		};
		Policy policy = new Policy();
		Predicate predicate = new Predicate("attribute1", Operation.EQ, new Attribute("some other string"));
		List<Predicate> predicates = new LinkedList<>();
		predicates.add(predicate);
		policy.setPredicates(predicates);
		try {
			authHandler.validateAssertions("username", policy);
			fail();
		} catch(Exception e) {
		}
		predicate = new Predicate("attribute2", Operation.EQ, new Attribute(10));
		predicates = new LinkedList<>();
		predicates.add(predicate);
		policy.setPredicates(predicates);
		try {
			authHandler.validateAssertions("username", policy);
			fail();
		} catch(Exception e) {
		}
		
		predicate = new Predicate("attribute3", Operation.EQ, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("10.10.1999")));
		predicates = new LinkedList<>();
		predicates.add(predicate);
		policy.setPredicates(predicates);
		try {
			authHandler.validateAssertions("username", policy);
			fail();
		} catch(Exception e) {
		}
	}
	
	@Test
	public void testValidateAssertionsLT() throws Exception {
		TestDb db = new TestDb();

		AuthenticationHandler authHandler = new AuthenticationHandler(db, null, new HashMap<>(), null ) {

			@Override
			public String requestMFASecret(String username, String type) throws Exception {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public String generateSessionCookie(String username) {
				// TODO Auto-generated method stub
				return null;
			}
			
		};
		Policy policy = new Policy();
		List<Predicate> predicates = new LinkedList<>();
		Predicate predicate = new Predicate("attribute2", Operation.LESSTHAN, new Attribute(15));
		predicates.add(predicate);
		predicate = new Predicate("attribute3", Operation.LESSTHAN, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("1.8.1981")));
		predicates.add(predicate);
		policy.setPredicates(predicates);

		Map<String, Attribute> response = authHandler.validateAssertions("username", policy);
		assertEquals(2, response.size());
		assertEquals(new Attribute(true), response.get("attribute2LT15"));
		assertEquals(new Attribute(true), response.get("attribute3LT01.08.81"));
	}
	
	@Test
	public void testValidateAssertionsBadLT() throws Exception {
		TestDb db = new TestDb();
		
		AuthenticationHandler authHandler = new AuthenticationHandler(db, null, new HashMap<>(), null ) {

			@Override
			public String requestMFASecret(String username, String type) throws Exception {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public String generateSessionCookie(String username) {
				// TODO Auto-generated method stub
				return null;
			}
			
		};
		
		Policy policy = new Policy();
		List<Predicate> predicates = new LinkedList<>();
		Predicate predicate = new Predicate("attribute2", Operation.LESSTHAN, new Attribute(14));
		predicates.add(predicate);
		policy.setPredicates(predicates);
		try {
			authHandler.validateAssertions("username", policy);
			fail();
		} catch(Exception e) {
		}
		predicates = new LinkedList<>();
		predicate = new Predicate("attribute3", Operation.LESSTHAN, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("8.1.1979")));
		predicates.add(predicate);
		policy.setPredicates(predicates);
		try {
			authHandler.validateAssertions("username", policy);
			fail();
		} catch(Exception e) {
		}
		
		predicates = new LinkedList<>();
		predicate = new Predicate("attribute1", Operation.LESSTHAN, new Attribute("25"));
		predicates.add(predicate);
		policy.setPredicates(predicates);
		try {
			authHandler.validateAssertions("username", policy);
			fail();
		} catch(Exception e) {
		}
	}
	
	@Test
	public void testValidateAssertionsGT() throws Exception {
		TestDb db = new TestDb();
		
		AuthenticationHandler authHandler = new AuthenticationHandler(db, null, new HashMap<>(), null ) {

			@Override
			public String requestMFASecret(String username, String type) throws Exception {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public String generateSessionCookie(String username) {
				// TODO Auto-generated method stub
				return null;
			}
			
		};
		Policy policy = new Policy();
		List<Predicate> predicates = new LinkedList<>();
		Predicate predicate = new Predicate("attribute2", Operation.GREATERTHAN, new Attribute(15));
		predicates.add(predicate);
		predicate = new Predicate("attribute3", Operation.GREATERTHAN, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("8.1.1970")));
		predicates.add(predicate);
		policy.setPredicates(predicates);

		Map<String, Attribute> response = authHandler.validateAssertions("username", policy);
		assertEquals(2, response.size());
		assertEquals(new Attribute(true), response.get("attribute2GT15"));
		assertEquals(new Attribute(true), response.get("attribute3GT08.01.70"));
	}
	
	@Test
	public void testValidateAssertionsBadGT() throws Exception {
		TestDb db = new TestDb();
		
		AuthenticationHandler authHandler = new AuthenticationHandler(db, null, new HashMap<>(), null ) {

			@Override
			public String requestMFASecret(String username, String type) throws Exception {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public String generateSessionCookie(String username) {
				// TODO Auto-generated method stub
				return null;
			}
			
		};
		
		Policy policy = new Policy();
		List<Predicate> predicates = new LinkedList<>();
		Predicate predicate = new Predicate("attribute2", Operation.GREATERTHAN, new Attribute(16));
		predicates.add(predicate);
		policy.setPredicates(predicates);
		try {
			authHandler.validateAssertions("username", policy);
			fail();
		} catch(Exception e) {
		}
		predicates = new LinkedList<>();
		predicate = new Predicate("attribute3", Operation.GREATERTHAN, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("02.01.1980")));
		predicates.add(predicate);
		policy.setPredicates(predicates);
		try {
			authHandler.validateAssertions("username", policy);
			fail();
		} catch(Exception e) {
		}
		
		predicates = new LinkedList<>();
		predicate = new Predicate("attribute1", Operation.GREATERTHAN, new Attribute("25"));
		predicates.add(predicate);
		policy.setPredicates(predicates);
		try {
			authHandler.validateAssertions("username", policy);
			fail();
		} catch(Exception e) {
		}
	}


	@Test
	public void testValidateAssertionsInRange() throws Exception {
		TestDb db = new TestDb();

		AuthenticationHandler authHandler = new AuthenticationHandler(db, new InMemoryKeyDB(), new HashMap<>(), null) {

			@Override
			public String requestMFASecret(String username, String type) throws Exception {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public String generateSessionCookie(String username) {
				// TODO Auto-generated method stub
				return null;
			}

		};
		Policy policy = new Policy();
		List<Predicate> predicates = new LinkedList<>();
		Predicate predicate = new Predicate("attribute2", Operation.INRANGE, new Attribute(14), new Attribute(16));
		predicates.add(predicate);
		predicate = new Predicate("attribute3", Operation.INRANGE, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("8.1.1970")),new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("8.1.1981")));
		predicates.add(predicate);
		policy.setPredicates(predicates);

		Map<String, Attribute> response = authHandler.validateAssertions("username", policy);
		assertEquals(2, response.size());
		assertEquals(new Attribute(true), response.get("attribute2INRANGE14-16"));
		assertEquals(new Attribute(true), response.get("attribute3INRANGE08.01.70-08.01.81"));
	}

	@Test
	public void testValidateAssertionsBadInRange() throws Exception {
		TestDb db = new TestDb();

		AuthenticationHandler authHandler = new AuthenticationHandler(db, new InMemoryKeyDB(), new HashMap<>(), null) {

			@Override
			public String requestMFASecret(String username, String type) throws Exception {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public String generateSessionCookie(String username) {
				// TODO Auto-generated method stub
				return null;
			}

		};

		Policy policy = new Policy();
		List<Predicate> predicates = new LinkedList<>();
		Predicate predicate = new Predicate("attribute2", Operation.INRANGE, new Attribute(16),new Attribute(17));
		predicates.add(predicate);
		policy.setPredicates(predicates);
		try {
			authHandler.validateAssertions("username", policy);
			fail();
		} catch(Exception e) {
		}
		predicate = new Predicate("attribute2", Operation.INRANGE, new Attribute(13),new Attribute(14));
		predicates.add(predicate);
		policy.setPredicates(predicates);
		try {
			authHandler.validateAssertions("username", policy);
			fail();
		} catch(Exception e) {
		}
		predicates = new LinkedList<>();
		predicate = new Predicate("attribute3", Operation.INRANGE, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("02.01.1980")), new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("03.01.1980")));
		predicates.add(predicate);
		policy.setPredicates(predicates);
		try {
			authHandler.validateAssertions("username", policy);
			fail();
		} catch(Exception e) {
		}
		predicate = new Predicate("attribute3", Operation.INRANGE, new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("01.01.1979")), new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("31.12.1979")));
		predicates.add(predicate);
		policy.setPredicates(predicates);
		try {
			authHandler.validateAssertions("username", policy);
			fail();
		} catch(Exception e) {
		}
		predicates = new LinkedList<>();
		predicate = new Predicate("attribute1", Operation.INRANGE, new Attribute("25"));
		predicates.add(predicate);
		policy.setPredicates(predicates);
		try {
			authHandler.validateAssertions("username", policy);
			fail();
		} catch(Exception e) {
		}
	}
	
	@Test
	public void testRefreshCookie() {
		UserAuthorizationDatabase db = new UserAuthorizationDatabase() {
			
			@Override
			public void storeCookie(String cookie, Authorization user) {
				if("BRnfu/oLHaTbG0E6Rlbb1GKExe0C/D5gO1ah2i8vjfaFDOez3H6JH0OPaVRelHcFgNc0BgYlEq31oB7JdCOBMw==".equals(cookie)) {
					return;
				}
				throw new RuntimeException("Simulated failure to store cookie");
			}
			
			@Override
			public Authorization lookupCookie(String cookie) {
				if("startCookie".equals(cookie) || "BRnfu/oLHaTbG0E6Rlbb1GKExe0C/D5gO1ah2i8vjfaFDOez3H6JH0OPaVRelHcFgNc0BgYlEq31oB7JdCOBMw==".equals(cookie)) {
					return new Authorization();
				} else throw new RuntimeException("cookie not found");
			}
			int counter = 0;
			@Override
			public void deleteCookie(String cookie) {
				if(counter != 0) {
					throw new RuntimeException("Planned fail to delete");
				}
				counter++;
			}
		};
		
				
		AuthenticationHandler handler = new AuthenticationHandler(null, db, new HashMap<>(), new TestCrypto()){			
			@Override
			public String requestMFASecret(String username, String type) throws Exception {
				// TODO Auto-generated method stub
				return null;
			}
			
			@Override
			public String generateSessionCookie(String username) {
				// TODO Auto-generated method stub
				return null;
			}
		};
		
		String resp = handler.refreshCookie("startCookie");
		assertEquals("BRnfu/oLHaTbG0E6Rlbb1GKExe0C/D5gO1ah2i8vjfaFDOez3H6JH0OPaVRelHcFgNc0BgYlEq31oB7JdCOBMw==", resp);
		// if something breaks in the refreshing process
		assertEquals("otherCookie", handler.refreshCookie("otherCookie"));
		resp = handler.refreshCookie("BRnfu/oLHaTbG0E6Rlbb1GKExe0C/D5gO1ah2i8vjfaFDOez3H6JH0OPaVRelHcFgNc0BgYlEq31oB7JdCOBMw==");
		assertEquals("BRnfu/oLHaTbG0E6Rlbb1GKExe0C/D5gO1ah2i8vjfaFDOez3H6JH0OPaVRelHcFgNc0BgYlEq31oB7JdCOBMw==", resp);
	}
	
	private class TestIP implements IdentityProver {

		protected boolean allCalled = false;
		public boolean hasBeenCalled() {
			return allCalled;
		}
		
		@Override
		public boolean isValid(String idProof, String username) {
			return false;
		}
		@Override
		public void addAttributes(String proof, String username) {
		}
	}
	
	class TestCrypto implements ServerCryptoModule {

		@Override
		public byte[] constructNonce(String username, long salt) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public byte[] hash(List<byte[]> bytes) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public byte[] getBytes(int noOfBytes) {
			return Base64.decodeBase64("BRnfu/oLHaTbG0E6Rlbb1GKExe0C/D5gO1ah2i8vjfaFDOez3H6JH0OPaVRelHcFgNc0BgYlEq31oB7JdCOBMw==");
		}

		@Override
		public PublicKey getStandardRSAkey() throws Exception {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public BigInteger getModulus() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public boolean verifySignature(PublicKey publicKey, List<byte[]> input, byte[] signature) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public BIG getRandomNumber() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public ECP hashToGroup1Element(byte[] input) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public byte[] sign(PublicKey publicKey, byte[] nonce, int myId) throws Exception {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public boolean setupServer(KeyShares share) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public byte[] combineSignatures(List<byte[]> partialSignatures) throws Exception {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public FP12 hashAndPair(byte[] bytes, ECP x) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public FP12 generateBlinding(String ssid, int myId) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public ECP2 hashToGroup2(byte[] input) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public byte[] sign(byte[] message) throws Exception {
			// TODO Auto-generated method stub
			return null;
		}
		
	}
	
	private class TestDb implements Storage {

		protected boolean allCalled = false;
		public boolean hasBeenCalled() {
			return allCalled;
		}
		
		@Override
		public boolean hasUser(String username) {
			return false;
		}

		@Override
		public Map<String, Attribute> getAttributes(String username) {
			Map<String, Attribute> map = new HashMap<String, Attribute>();
			map.put("attribute1", new Attribute("13"));
			map.put("attribute2", new Attribute(15));
			try {
				map.put("attribute3", new Attribute(DateFormat.getDateInstance(DateFormat.SHORT, Locale.GERMAN).parse("01.01.1980")));
			} catch (ParseException e) {
			}
			return map;
		}

		@Override
		public void addAttributes(String username, Map<String, Attribute> attributes) {
		}

		@Override
		public void addAttribute(String username, String key, Attribute value) {
		}

		@Override
		public boolean deleteAttribute(String username, String attributeName) {
			return true;
		}

		@Override
		public boolean deleteUser(String username) {
			return true;
		}

		@Override
		public void assignMFASecret(String username, String type, String secret) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public Map<String, MFAInformation> getMFAInformation(String username) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public void activateMFA(String username, String type) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void deleteMFA(String username, String type) {
			// TODO Auto-generated method stub
		}
	}
}
