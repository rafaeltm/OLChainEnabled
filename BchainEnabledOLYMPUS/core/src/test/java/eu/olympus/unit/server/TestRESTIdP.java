package eu.olympus.unit.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import eu.olympus.model.Authorization;
import eu.olympus.model.server.rest.AddPartialSignatureRequest;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.TestParameters;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.rest.PestoIdPServlet;
import eu.olympus.server.rest.PestoRESTEndpoints;
import eu.olympus.server.rest.RESTIdPServer;
import eu.olympus.server.rest.Role;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.junit.Test;

public class TestRESTIdP {
	
	private boolean addPartialReached = false;
	@Test
	public void testBasic() throws Exception {
		RESTIdPServer server = new RESTIdPServer();
		PestoDatabase authDatabase = new InMemoryPestoDatabase();
		PestoIdPImpl testIdP = new PestoIdPImpl(authDatabase,  new ArrayList<>(), new HashMap<String, MFAAuthenticator>(), new SoftwareServerCryptoModule(new Random(1))) {
			@Override
			public void addPartialServerSignature(String ssid, byte[] signature) {
				addPartialReached = true;
			}
		};
		server.setIdP(testIdP);
		
		testIdP.addSession("authToken", new Authorization("user", Arrays.asList(new Role[] {Role.SERVER}), System.currentTimeMillis()+10000l));
		List<String> types = new ArrayList<String>();
		types.add(PestoIdPServlet.class.getCanonicalName());
		
		server.start(10666, types, 10667, null, null, null);

		Client client = ClientBuilder.newClient();

		AddPartialSignatureRequest request = new AddPartialSignatureRequest("ssid", "signature");
		Response response = client.target("http://localhost:10666/idp/"+ PestoRESTEndpoints.ADD_PARTIAL_SIGNATURE).request().header("Authorization", "Bearer authToken").post(Entity.entity(request, MediaType.APPLICATION_JSON));
		
		server.stop();
		assertTrue(addPartialReached);
		assertEquals(204, response.getStatus());
	}

	private boolean addPartialReachedTLS = false;
	
	@Test
	public void testTLS() throws Exception {
		RESTIdPServer server = new RESTIdPServer();
		PestoDatabase authDatabase = new InMemoryPestoDatabase();
		PestoIdPImpl testIdP = new PestoIdPImpl(authDatabase, new ArrayList<>(), new HashMap<String, MFAAuthenticator>(), new SoftwareServerCryptoModule(new Random(1))) {
			@Override
			public void addPartialServerSignature(String ssid, byte[] signature) {
				addPartialReachedTLS = true;
			}
		};
		server.setIdP(testIdP);
		
		testIdP.addSession("authToken", new Authorization("user", Arrays.asList(new Role[] {Role.SERVER}), System.currentTimeMillis()+10000l));
		
		List<String> types = new ArrayList<String>();
		types.add(PestoIdPServlet.class.getCanonicalName());
		
		server.start(10666, types, 10667, TestParameters.TEST_KEY_STORE_LOCATION, TestParameters.TEST_KEY_STORE_PWD, TestParameters.TEST_KEY_STORE_PWD);
		

		Client client = ClientBuilder.newClient();
		AddPartialSignatureRequest request = new AddPartialSignatureRequest("ssid", "signature");
		Response response = client.target("http://localhost:10666/idp/"+PestoRESTEndpoints.ADD_PARTIAL_SIGNATURE).request().header("Authorization", "Bearer authToken").post(Entity.entity(request, MediaType.APPLICATION_JSON));
		
		server.stop();
		assertTrue(addPartialReachedTLS);
		assertEquals(204, response.getStatus());
	}
}
