package eu.olympus.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import eu.olympus.model.*;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.util.psmultisign.PSverfKey;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.*;

import org.apache.commons.codec.binary.Base64;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import eu.olympus.TestParameters;
import eu.olympus.model.Attribute;
import eu.olympus.model.Authorization;
import eu.olympus.model.MFAInformation;
import eu.olympus.model.Policy;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.Operation;
import eu.olympus.model.Predicate;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.rest.AuthenticationFilter;
import eu.olympus.server.rest.PestoIdPServlet;
import eu.olympus.server.rest.RESTIdPServer;
import eu.olympus.server.rest.Role;

import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.FP12;

public class TestPestoIdPRESTConnection {

	private static RESTIdPServer server = new RESTIdPServer();
	private static final String url = "http://127.0.0.1:8666";
	private static final String fp12String = "CCX3MY6l5x691jSy"
			+ "NJKM8Q3BKGPiWJQt8zYkhATkkYNT7of"
			+ "4OBnhQJdGxU3Tf1gQ+pprdhTI57mMHQ0rcnrycDqG8QuDYc11oh0+cu"
			+ "KFR01XWojvSGGcU+FLzM7wpWNmKG1qI4iVW/vyUzoK6Xxj1c5po+kG7"
			+ "hMZe3NEeAzzXhbTZUUjydnQaTGG2iKo2/rwMM3EvbcX3HVG8VlK2mqq"
			+ "usVYyKKRIRNdbLdJLmK/EFwGMFAOIsJR8hlk8dZQS5dUdjC4uUk1dCT"
			+ "dkieiII21MBSoTzwavllqooJ0ITnWJBXtdxJpnoU1lBQJIzSQT+gIq5"
			+ "PxLYcmuANfxEv8Tpf9ayqDjTr0GWHNAxMYYV5gP0RrLv96gEOYc98W7"
			+ "rS8GE6HrKUJqrkW+JTAUzHbgCd5+a61sDT+M/qUExZxrINT+JPVXaio"
			+ "TUwvHs6PiykYsnJUJV6jHpdty0skbJ0rC4vWxPlcX8pB6MVhqeokKd0"
			+ "0Q6on125OUtq5LgV5RgSFO9i2c8PbCvakUx/UFr8fdD/Jrf3JWOmfYQ"
			+ "gf/Cxv86hovCepIs9rvs0wbprmEKvsdLJlVnjRnhtvfSKTjQnUnMph9"
			+ "KX6Y2y6OFy02aNfjt0J7REB0VidQJKK/74gEHMB3mbmi3ChqqVaRU5l"
			+ "a2J5OHzhSFhoZyIF/5VckCpyJiiV8vlLNDVKzglIJ1LyCepVeJO3rYj"
			+ "tK+bqSSTs4pxE5C8n2TzPpHcv4ZO3crP4qIzWbSEAdRde+YXQUw3fOc"
			+ "tSrgmBd+mPnwwgDotTsuOCztaMFHjttwHYvFUWVbYWwQEIWDW9qVaDM"
			+ "in/IB0AjklFyzHr7w9gN2GBS0vQOS4Zn0gMlTbLbdHc+aVxVDp28zo7"
			+ "Yz4zsNM9z3XeWm6/1L7wawqxQhM7FdSiZInyDzqU0kRubYGXva2e5CZ"
			+ "i";
	private static final FP12 fp12 = FP12.fromBytes(Base64.decodeBase64(fp12String));
	private static final String publicParamString = "CAMSTAoyZXUub2x5b"
			+ "XB1cy51dGlsLnBhaXJpbmdCTFM0NjEuUGFpcmluZ0J1aWxkZXJCTFM0"
			+ "NjESC05hdGlvbmFsaXR5EgNBZ2USBE5hbWU=";

	private static final String psVerfKeyString = "CnoKeAo6EisbfOFyTuo"
		    + "KozbyRISSwM85o5IXfiYZltcKGwoHoVFoHkBXJvnjn8YDczF/nZ8sdu"
			+ "/8QpHsMZX4IhI6B7/noK3X0V5VAZ7cHLJNypLqZWxSgqwMKDwj7Yk7k"
			+ "9L7j4Dk9S1u5zf2h3t5dQO04KT3111w1baUBRJ6CngKOhLrSyt1mP/V"
			+ "9WdMeO9EOSxLNKSGARwEHyktfSMVtoeDp9vMXNkUPJi70CV82k0rhF/"
			+ "3lFllvfuhFlQSOgk9TB/91EjG93BwdeZBKWDTkV3lhGGGCU2Lon4goo"
			+ "7Jmu4E0yAsy3Cw45/nCXziiu/l5vBiXm9/j68aegp4CjoQfH7QJG1AX"
			+ "oKkLQ0d7jWqFKV3eXpvGa7MiDB2miyW8y/SXxnT/ANYrLboa9YuZMQz"
			+ "UAL1F8MXI9b6EjoJlBYVWdBNKysboy8Ii4+ioiFmfTY4FlRSIZwLIj3"
			+ "V0gqscd0xjSSQKFxoBMtIe6oIGI4+eT/MvGBQIoEBCgNOb3cSegp4Cj"
			+ "oABFx2HPX7IrN/u40TelnmU8QcMvCL4iiWmB3Pw2hq3eeBB8L+9ycKu"
			+ "9Xrl0pDCEpeKGNKcb4XCJwfEjoBaQxyimDo/Q/Q8j4fiWz/+DYcTF9a"
			+ "BlCxz8NMg4j9do2La6juzzckAcK22K23wzdxR4/ySjF2IAjOIoEBCgN"
			+ "BZ2USegp4CjoQ1TdDVXwg4HowwLLNwo3dhvs8BpC6EvUHKQQKb3eBwh"
			+ "eajbWFrHWcciBqILv/fyWKzSMZ0STBiY+1EjoE//2Jqk0zpzJt10Vg2"
			+ "IZ/EZMhIPeVf21HfWGcTCEHuwYQEChVu4lrwRRZA7BbzXvUP0l9y3YS"
			+ "QjhnIoIBCgROYW1lEnoKeAo6AzuLurQtXjxmt9nHOisR7THToYYnL/G"
			+ "vqh43HAHdpwv75iO1QtORycj7UL4vIAJop8VuvE+eAWkKoRI6BBMy5B"
			+ "G+qKntrFM5Z4k2pR7ToSp3zH4UYCKDNcZhXpiy0IjqpVG/4dGrciQY6"
			+ "x/gepIjOKl8ROOSrA==";

	private static boolean performOPRFMFAReached = false;
	private static boolean finishRegistrationReached = false;
	private static boolean authenticateReached = false;
	private static boolean addAttributesReached = false;
	private static boolean getPublicKeyReached = false;
	private static boolean getAllAttributesReached = false;
	private static boolean deleteAttributesReached = false;
	private static boolean deleteAccountReached = false;
	private static boolean changePasswordReached = false;
	private static boolean obtainCredentialReached = false;
	private static boolean getPabcPublicKeyReached = false;
	private static boolean getPublicParamReached = false;
	private static boolean startRefreshReached = false;




	@BeforeClass
	public static void startServer() throws Exception {
		PestoDatabase authDB = new InMemoryPestoDatabase() {
			@Override
			public Map<String, MFAInformation> getMFAInformation(String username) {
				return new HashMap<>();
			}
			
			@Override
			public boolean hasUser(String user) {
				return true;
			}
		};
		PestoIdPImpl testIdP = new PestoIdPImpl(authDB, new ArrayList<>(), new HashMap<String, MFAAuthenticator>(),new SoftwareServerCryptoModule(new Random(1))) {
			@Override
			public void addPartialServerSignature(String ssid, byte[] signature) {
				fail();
			}

			@Override
			public OPRFResponse performOPRF(String ssid, String username, ECP x, String mfaToken, String mfaType) throws UserCreationFailedException {
				performOPRFMFAReached = true;
				return new OPRFResponse(fp12, "ssid", "session");
			}
			
			@Override
			public byte[] finishRegistration(String username, byte[] cookie, PublicKey publicKey, byte[] signature, long salt, String idProof) throws Exception {
				if("user2".equals(username)) {
					throw new Exception("Bad server response");
				}
				assertEquals("username", username);
				assertEquals(TestParameters.getRSAPublicKey1(), publicKey);
				assertEquals("signature", new String(signature));
				assertEquals(1000, salt);
				assertEquals("idProof", idProof);
				finishRegistrationReached = true;
				return "reply".getBytes();
			}

			@Override
			public String authenticate(String username, byte[] cookie, long salt, byte[] signature, Policy policy) throws Exception {
				assertEquals("username", username);
				assertEquals("name", policy.getPredicates().get(0).getAttributeName());
				assertEquals(1, policy.getPredicates().size());
				assertEquals("signature", new String(signature));
				assertEquals(1000, salt);
				authenticateReached = true;
				return "token";
			}

			@Override
			public Certificate getCertificate() {
				if(getPublicKeyReached) {
					throw new RuntimeException();
				}
				getPublicKeyReached = true;
				return TestParameters.getRSA1Cert();
			}

			@Override
			public boolean addAttributes(String username, byte[] cookie, long salt, byte[] signature, String idProof) {
			
				assertEquals("username", username);
				assertEquals("signature", new String(signature));
				assertEquals(1000, salt);
				assertEquals("idProof", idProof);
				addAttributesReached = true;
				return true;
			}

			@Override
			public Map<String, Attribute> getAllAttributes(String username, byte[] cookie, long salt, byte[] signature) {
				assertEquals("username", username);
				assertEquals("sig", new String(signature));
				assertEquals(200, salt);
				getAllAttributesReached = true;
				HashMap<String, Attribute> attr = new HashMap<String, Attribute>();
				attr.put("name", new Attribute("John"));
				return attr;
			}

			@Override
			public boolean deleteAttributes(String username, byte[] cookie, long salt, byte[] signature, List<String> attributes) {
				assertEquals("username", username);
				assertEquals("signature", new String(signature));
				assertEquals(300, salt);
				assertEquals("name", attributes.get(0));
				assertEquals(1, attributes.size());
				deleteAttributesReached = true;
				return true;
			}

			@Override
			public boolean deleteAccount(String username, byte[] cookie, long salt, byte[] signature) {
				assertEquals("user", username);
				assertEquals("signature", new String(signature));
				assertEquals(10, salt);
				deleteAccountReached = true;
				return true;
			}

			@Override
			public byte[] changePassword(String username, byte[] cookie, PublicKey publicKey, byte[] oldSignature, byte[] newSignature, long salt) throws Exception {
				assertEquals("username", username);
				assertEquals(TestParameters.getECPublicKey2(), publicKey);
				assertEquals("oldsignature", new String(oldSignature));
				assertEquals("newsignature", new String(newSignature));
				assertEquals(100, salt);
				changePasswordReached = true;
				return "response".getBytes();
			}

			@Override
			public String getCredentialShare(String username, byte[] cookie, long salt, byte[] share, long time) throws Exception {
				assertEquals("user", username);
				assertEquals(0, salt);
				assertEquals("some-pretty-long-and-winding-share", new String(share));
				assertEquals(1000, time);
				obtainCredentialReached = true;
				return "credential";
			}

			@Override
			public MSverfKey getPabcPublicKeyShare() {
				if(getPabcPublicKeyReached) {
					throw new RuntimeException();
				}
				getPabcPublicKeyReached = true;
				try {
					return new PSverfKey(Base64.decodeBase64(psVerfKeyString));
				}catch (Exception e) {
					return null;
				}
			}

			@Override
			public PabcPublicParameters getPabcPublicParam() {
				if(getPublicParamReached) {
					throw new RuntimeException();
				}
				getPublicParamReached = true;
				try {
					AttributeDefinition def=new AttributeDefinitionString("Name","Name",1,16);
					Set<AttributeDefinition> defs=new HashSet<>();
					defs.add(def);
					PabcPublicParameters as=new PabcPublicParameters(defs,publicParamString);
					return as;
				}catch(Exception e) {
					e.printStackTrace();
					return null;
				}
			}

			@Override
			public boolean startRefresh() {
				startRefreshReached = true;
				return true;
			}

		};
		server.setIdP(testIdP);
		
		testIdP.addSession("admin", new Authorization("admin", Arrays.asList(new Role[] {Role.ADMIN}), System.currentTimeMillis()+10000l));
		List<String> types = new ArrayList<String>();
		types.add(PestoIdPServlet.class.getCanonicalName());
		types.add(AuthenticationFilter.class.getCanonicalName());

		server.start(8666, types, 8667, null, null, null);
	}

	@AfterClass
	public static void stopServer() throws Exception {
		server.stop();
	}

	@Test
	public void testPerformOPRFMFA() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		OPRFResponse response = connection.performOPRF("ssid", "username", ECP.generator(), "", "NONE");
		assertTrue(performOPRFMFAReached);
		assertEquals("ssid", response.getSsid());
		byte[] bytes = new byte[696]; 
		response.getY().toBytes(bytes);
		assertEquals(fp12String, Base64.encodeBase64String(bytes));
	}

	@Test
	public void testStartRefresh() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		boolean response = connection.startRefresh();
		assertFalse(startRefreshReached);
		assertFalse(response);
		connection = new PestoIdPRESTConnection(url, "admin", 0);
		response = connection.startRefresh();
		assertTrue(startRefreshReached);
		assertTrue(response);
	}

	@Test (expected = RuntimeException.class)
	public void testAddPartialSignature() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		connection.addPartialServerSignature("ssid", "username".getBytes());
		fail();
	}

	@Test (expected = RuntimeException.class)
	public void testAddPartialMFASecret() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		connection.addPartialMFASecret("ssid", "username", "authenticator_type");
		fail();
	}
	
	@Test (expected = RuntimeException.class)
	public void testAddMasterShare() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		connection.addMasterShare("ssid", "some-pretty-long-and-winding-share".getBytes());
		fail();
	}

	@Test (expected = RuntimeException.class)
	public void TestSetKeyShare() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		connection.setKeyShare(0, "some-pretty-long-and-winding-share".getBytes());
		fail();
	}

	@Test
	public void TestObtainCredential() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		String credential = connection.getCredentialShare("user", "session".getBytes(), 0, "some-pretty-long-and-winding-share".getBytes(), 1000);
		assertTrue(obtainCredentialReached);
		assertEquals("credential", credential);
	}

	@Test
	public void TestGetPabcPublicKey() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		MSverfKey key = connection.getPabcPublicKeyShare();
		assertTrue(getPabcPublicKeyReached);
		assertEquals(psVerfKeyString, Base64.encodeBase64String(key.getEncoded()));
		key = connection.getPabcPublicKeyShare();
		assertNull(key);
	}

	@Test
	public void TestGetPabcPublicParam() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		PabcPublicParameters params = connection.getPabcPublicParam();
		assertTrue(getPublicParamReached);
		assertEquals(publicParamString, params.getEncodedSchemePublicParam());
		params = connection.getPabcPublicParam();
		assertNull(params);
	}

	@Test
	public void TestGetId() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		assertEquals(0, connection.getId());
	}

	@Test
	public void testFinishRegistration() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		byte[] response = connection.finishRegistration("username", "session".getBytes(), TestParameters.getRSAPublicKey1(), "signature".getBytes(), 1000, "idProof");
		assertTrue(finishRegistrationReached);
		assertEquals("reply", new String(response));
	}

	@Test (expected = UserCreationFailedException.class)
	public void testFinishRegistrationException() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		connection.finishRegistration("user2", "session".getBytes(), TestParameters.getRSAPublicKey1(), "signature".getBytes(), 1000, "idProof");
		fail();
	}

	@Test
	public void testAuthenticate() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		Policy policy = new Policy();
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		policy.setPredicates(predicates);
		String reply = connection.authenticate("username", "session".getBytes(), 1000, "signature".getBytes(), policy);
		assertTrue(authenticateReached);
		assertEquals("token", reply);

	}

	@Test
	public void testAddAttributes() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		assertTrue(connection.addAttributes("username", "session".getBytes(), 1000, "signature".getBytes(), "idProof"));
		assertTrue(addAttributesReached);
	}


	@Test
	public void testGetPublicKey() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		Certificate cert = connection.getCertificate();
		assertTrue(getPublicKeyReached);
		assertEquals(cert, TestParameters.getRSA1Cert());
		try {
			connection.getCertificate();
			fail();
		} catch (RuntimeException e) {
			// Expected
		}
	}

	@Test
	public void testGetAllAttributes() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		Map<String, Attribute> attributes = connection.getAllAttributes("username", "session".getBytes(), 200, "sig".getBytes());
		assertTrue(getAllAttributesReached);
		assertEquals(new Attribute("John"), attributes.get("name"));
		assertEquals(1, attributes.size());
	}

	@Test
	public void testDeleteAttributes() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		List<String> attributes = new ArrayList<String>();
		attributes.add("name");
		assertTrue(connection.deleteAttributes("username", "session".getBytes(), 300, "signature".getBytes(), attributes));
		assertTrue(deleteAttributesReached);
	}

	@Test
	public void testDeleteAccount() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		assertTrue(connection.deleteAccount("user", "session".getBytes(), 10, "signature".getBytes()));
		assertTrue(deleteAccountReached);
	}

	@Test
	public void testChangePassword() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		byte[] response = connection.changePassword("username", "session".getBytes(), TestParameters.getECPublicKey2(), "oldsignature".getBytes(), "newsignature".getBytes(), 100);
		assertTrue(changePasswordReached);
		assertEquals("response", new String(response));
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testAddSession() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		connection.addSession("cookie", new Authorization());
		fail();
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testValidateSession() throws Exception {
		PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0);
		connection.validateSession("cookie", Arrays.asList(Role.USER));
		fail();
	}
}
