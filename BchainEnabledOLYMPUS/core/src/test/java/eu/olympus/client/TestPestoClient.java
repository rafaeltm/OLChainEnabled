package eu.olympus.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import eu.olympus.server.storage.InMemoryPestoDatabase;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import eu.olympus.model.Policy;
import eu.olympus.model.KeyShares;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.Operation;
import eu.olympus.model.Predicate;

import org.junit.Before;
import org.junit.Test;

import eu.olympus.TestParameters;
import eu.olympus.model.RSASharedKey;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.interfaces.Storage;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.FP12;


public class TestPestoClient {
	
	private ServerCryptoModule sCryptoModule = new SoftwareServerCryptoModule(new Random(1));
	private SoftwareClientCryptoModule cCryptoModule = null;
	
	@Before
	public void setupCrypto() throws Exception{
		RSAPrivateKey pk = TestParameters.getRSAPrivateKey1();
		BigInteger d = pk.getPrivateExponent();
		RSASharedKey keyMaterial = new RSASharedKey(pk.getModulus(), d, TestParameters.getRSAPublicKey1().getPublicExponent());
		Map<Integer, BigInteger> rsaBlindings = new HashMap<>();
		rsaBlindings.put(0, BigInteger.ONE);
		BigInteger oprfKey = new BigInteger("42");
		sCryptoModule.setupServer(new KeyShares(keyMaterial, rsaBlindings, oprfKey, null));
		cCryptoModule = new SoftwareClientCryptoModule(new Random(1), pk.getModulus());
	}
	
	@Test
	public void testAuthenticate() throws Exception {
		List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
		TestIdP idp = new TestIdP(new InMemoryPestoDatabase(), 1, null);
		
		idps.add(idp);
		PestoClient authClient = new PestoClient(idps, cCryptoModule);
		
		Policy policy = new Policy();
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		policy.setPredicates(predicates);
		
		String token = authClient.authenticate("username", "password", policy, null, "NONE");
		assertEquals("token", token);
	}
	
	@Test
	public void testAuthenticateServerThrowsException() throws Exception {
		List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
		TestIdP idp = new TestIdP(new InMemoryPestoDatabase(), 1, null) {
			@Override
			public String authenticate(String username, byte[] cookie, long salt, byte[] signature, Policy policy) {
				throw new RuntimeException("simulated server failure");
			}
		};
		idps.add(idp);
		PestoClient authClient = new PestoClient(idps, cCryptoModule);
		
		Policy policy = new Policy();
		List<Predicate> predicates = new ArrayList<>();
		Predicate predicate = new Predicate();
		predicate.setAttributeName("name");
		predicate.setOperation(Operation.REVEAL);
		predicates.add(predicate);
		policy.setPredicates(predicates);
		
		try {
			authClient.authenticate("username", "password", policy, null, "NONE");
			fail();
		} catch(AuthenticationFailedException e) {
		}
	}

	private class TestIdP extends PestoIdPImpl {

		public TestIdP(Storage database, int id, List<IdentityProver> identityProvers) throws Exception {
			super(database, identityProvers, new HashMap<String, MFAAuthenticator>(), new SoftwareServerCryptoModule(new Random(1)));
		}
		
		@Override
		public String authenticate(String username, byte[] cookie, long salt, byte[] signature, Policy policy) {
			assertEquals("username", username);
			assertEquals(1, policy.getPredicates().size());
			assertEquals("name", policy.getPredicates().get(0).getAttributeName());
			return "token";
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
