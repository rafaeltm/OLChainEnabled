package eu.olympus.unit.server.rest;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import eu.olympus.TestParameters;
import eu.olympus.model.Authorization;
import eu.olympus.model.PABCConfigurationImpl;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.rest.PestoIdP2IdPRESTConnection;
import eu.olympus.server.rest.PestoIdPServlet;
import eu.olympus.server.rest.RESTIdPServer;
import eu.olympus.server.rest.Role;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import eu.olympus.util.keyManagement.CertificateUtil;
import eu.olympus.util.keyManagement.SecureStoreUtil;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import org.junit.Ignore;
import org.junit.Test;

public class TestPestoIdP2IdPRESTConnection {
	
	private boolean addPartialReached = false;
	private boolean addMasterReached = false;
	private boolean setKeyShareReached = false;
	

	@Test
	public void testBasic() throws Exception {
		RESTIdPServer server = new RESTIdPServer();
		PestoDatabase db = new InMemoryPestoDatabase();
		PestoIdPImpl testIdP = new PestoIdPImpl(db,  new ArrayList<>(), new HashMap<String, MFAAuthenticator>(), new SoftwareServerCryptoModule(new Random(1))) {

			@Override
			public void addPartialServerSignature(String ssid, byte[] signature) {
				addPartialReached = true;
			}
			
			@Override
			public void addMasterShare(String newSsid, byte[] newShares) {
				addMasterReached = true;
			}
			
			@Override
			public void setKeyShare(int id, byte[] newShares) {
				setKeyShareReached = true;
			}
		};
		server.setIdP(testIdP);
		
		List<String> types = new ArrayList<String>();
		types.add(PestoIdPServlet.class.getCanonicalName());
		
		testIdP.addSession("server1", new Authorization("user",  Arrays.asList(new Role[]{Role.SERVER}), System.currentTimeMillis()+10000l));
		
		server.start(10666, types, 10667, null, null, null);

		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"bad_token");
		connection.addPartialServerSignature("ssid", "signature".getBytes());
		assertFalse(addPartialReached);
		connection.addMasterShare("newSsid", "newShare".getBytes());
		assertFalse(addMasterReached);
		connection.setKeyShare(1, "newShare".getBytes());
		assertFalse(setKeyShareReached);
		connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1, "server1");
		connection.addPartialServerSignature("ssid", "signature".getBytes());
		connection.addMasterShare("newSsid", "newShare".getBytes());
		connection.setKeyShare(1, "newShare".getBytes());
		
		server.stop();
		assertTrue(addPartialReached);
		assertTrue(addMasterReached);
		assertTrue(setKeyShareReached);
	}

	@Ignore
	@Test(expected = CertificateException.class)
	public void testWrongDomainCert() throws Exception {
		KeyStore ks = SecureStoreUtil.getEmptySecurityStore();
		Certificate cert = CertificateUtil.loadCertificate(TestParameters.TEST_DIR +"testCert.crt");
		ks.setCertificateEntry("testCert", cert);
		SecureStoreUtil.writeSecurityStore(ks, "password", TestParameters.TEST_DIR +"testStoreWrongDomain");

		PestoIdP idp = new PestoIdPImpl(new InMemoryPestoDatabase(), new LinkedList<IdentityProver>(),
				new HashMap<>(), new SoftwareServerCryptoModule(new Random(0)));
		RESTIdPServer restServer = new RESTIdPServer();
		restServer.setIdP(idp);
		List<String> types = new ArrayList<String>();
		types.add(PestoIdPServlet.class.getCanonicalName());
//		restServer.start(10666, types, 10667, TestParameters.TEST_DIR +"testStoreWrongDomain", "password", "password" );
		restServer.start(10666, types, 10667, TestParameters.TEST_KEY_STORE_LOCATION, TestParameters.TEST_KEY_STORE_PWD, TestParameters.TEST_KEY_STORE_PWD );
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"token");
		PABCConfigurationImpl conf = new PABCConfigurationImpl(); // TODO once we can actually load configuration with ObjectMapper. I.e. after OIDC-front has been merged
		conf.setMyAuthorizationCookies("token");
		assertTrue(((PestoIdPImpl) idp).setup("setup", conf, Arrays.asList(connection)));
		connection.addPartialServerSignature("test", "test".getBytes()); // TODO assert that the right error occurs, probably will have to inspect error code
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testGetPublicKey() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"Bearer auth");
		connection.getCertificate();
		fail();
	}
	
	@Test(expected = UnsupportedOperationException.class)
	public void testFinishRegistration() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"Bearer auth");
		connection.finishRegistration("", "session".getBytes(), null, "byte".getBytes(), 0, null);
		fail();
	}
	
	@Test(expected = UnsupportedOperationException.class)
	public void testAuthenticate() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"Bearer auth");
		connection.authenticate(null, "session".getBytes(), 0, null, null);
		fail();
	}
	
	@Test(expected = UnsupportedOperationException.class)
	public void testObtainCredential() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1, "Bearer auth");
		connection.getCredentialShare(null, "session".getBytes(), 0, null, 0);
		fail();
	}
	
	@Test(expected = UnsupportedOperationException.class)
	public void testGetPabcPublicKey() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1, "Bearer auth");
		connection.getPabcPublicKeyShare();
		fail();
	}
	
	@Test(expected = UnsupportedOperationException.class)
	public void testGetPabcPublicParam() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"Bearer auth");
		connection.getPabcPublicParam();
		fail();
	}
	
	@Test(expected = UnsupportedOperationException.class)
	public void testAddAttributes() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1, "Bearer auth");
		connection.addAttributes(null, "session".getBytes(), 0, null, null);
		fail();
	}
	
	@Test(expected = UnsupportedOperationException.class)
	public void testGetAllAttributes() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"Bearer auth");
		connection.getAllAttributes(null, "session".getBytes(), 0, null);
		fail();
	}
	
	@Test(expected = UnsupportedOperationException.class)
	public void testDeleteAttributes() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"Bearer auth");
		connection.deleteAttributes(null, "session".getBytes(), 0, null, null);
		fail();
	}
	
	@Test(expected = UnsupportedOperationException.class)
	public void testDeleteAccount() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"Bearer auth");
		connection.deleteAccount(null, "session".getBytes(), 0, null);
		fail();
	}
	
	@Test(expected = UnsupportedOperationException.class)
	public void testChangePassword() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"Bearer auth");
		connection.changePassword(null, "session".getBytes(), null, null, null, 0);
		fail();
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testPerformOPRFMFA() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"Bearer auth");
		connection.performOPRF(null, null, null, null, null);
		fail();
	}
	
	@Test(expected = UnsupportedOperationException.class)
	public void testStartRefresh() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"Bearer auth");
		connection.startRefresh();
		fail();
	}
	
	@Test(expected = UnsupportedOperationException.class)
	public void testConfirmMFA() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"Bearer auth");
		connection.confirmMFA(null, "session".getBytes(), 0, null, null, null);
		fail();
	}
	
	@Test(expected = UnsupportedOperationException.class)
	public void testRequestMFA() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"Bearer auth");
		connection.requestMFA(null, "session".getBytes(), 0, null, null);
		fail();
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testRemoveMFA() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"Bearer auth");
		connection.removeMFA(null, "session".getBytes(), 0, null, null, null);
		fail();
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testAddSession() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"Bearer auth");
		connection.addSession("cookie", new Authorization());
		fail();
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testValidateSession() throws Exception {
		PestoIdP2IdPRESTConnection connection = new PestoIdP2IdPRESTConnection("http://localhost:10666", 1,
				"Bearer auth");
		connection.validateSession("cookie", Arrays.asList(Role.USER));
		fail();
	}

}
