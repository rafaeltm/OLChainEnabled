package eu.olympus.cfp;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import eu.olympus.TestParameters;
import eu.olympus.cfp.model.CreditFile;
import eu.olympus.cfp.model.TokenIdentityProof;
import eu.olympus.cfp.model.UserCertificate;
import eu.olympus.cfp.server.identityprovers.CreditFileIdentityProver;
import eu.olympus.cfp.server.identityprovers.TokenIdentityProver;
import eu.olympus.cfp.server.identityprovers.UserCredentialIdentityProver;
import eu.olympus.cfp.verifier.JWTVerifier;
import eu.olympus.client.PasswordJWTClient;
import eu.olympus.client.PestoClient;
import eu.olympus.client.PestoIdPRESTConnection;
import eu.olympus.client.SoftwareClientCryptoModule;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.model.AttributeDefinitionString;
import eu.olympus.model.Operation;
import eu.olympus.model.PABCConfigurationImpl;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.model.RSASharedKey;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.server.PasswordJWTIdP;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.interfaces.Storage;
import eu.olympus.server.interfaces.UserPasswordDatabase;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import eu.olympus.server.storage.InMemoryUserPasswordDatabase;
import eu.olympus.util.CommonCrypto;
import eu.olympus.verifier.interfaces.Verifier;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public class TestFlow {
	private List<IdentityProver> identityProvers = null;
	private Storage storage = null;
	private Certificate certificate = null;

	@Before
	public void setupIdProvers() throws Exception { 
		identityProvers = new LinkedList<IdentityProver>();
		
		//Adds an unvalidated token prover
		identityProvers.add(new TokenIdentityProver(storage));
		
		//Adds a creditfile to the attributes. creditfile is validate with "pathToCert" as CTI cert and dynamically loads user cert 
		identityProvers.add(new CreditFileIdentityProver("src/test/resources/signerCertificate.cer", storage)); //Takes a static CTI cert as trust.	
		
		//Validates a cert wrt. root signature. Supplied pathToCert is the root (Who owns the signing cert?)
		identityProvers.add(new UserCredentialIdentityProver("src/test/resources/signerCertificate.cer", storage)); //Takes a static CTI cert as trust.
		
		certificate = loadCertificate("src/test/resources/012345678A_PF_HSM_Test05.crt");
	}
	
	@Ignore
	@Test
	public void testPasswordJWTDirect() throws CertificateEncodingException{
		UserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		PasswordJWTIdP idp = null;
		try {
			idp = new PasswordJWTIdP(db, identityProvers, new HashMap<>());
		} catch(Exception e) {
			fail("Failed to start IdP");
		}
		List<PasswordJWTIdP> idps = new ArrayList<PasswordJWTIdP>();
		idps.add(idp);
		UserClient client = new PasswordJWTClient(idps);
		try{
			idp.setup(TestParameters.getRSAPrivateKey1(), TestParameters.getRSA1Cert());
		} catch(Exception e) {
			fail("Failed to generate key");
		}
		Verifier verifier = new JWTVerifier(idp.getCertificate().getPublicKey());
		testCreateTwoStepFlow(client, verifier);
	}

	
	@Ignore
	@Test
	public void testPestoRunning() throws Exception{

		Properties systemProps = System.getProperties();

		systemProps.put("javax.net.ssl.keyStorePassword", TestParameters.TEST_KEY_STORE_PWD);
		systemProps.put("javax.net.ssl.keyStore", TestParameters.TEST_KEY_STORE_LOCATION);
		systemProps.put("javax.net.ssl.trustStore", TestParameters.TEST_TRUST_STORE_LOCATION);
		systemProps.put("javax.net.ssl.trustStorePassword", TestParameters.TEST_TRUST_STORE_PWD);
		System.setProperties(systemProps);

		javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
				new javax.net.ssl.HostnameVerifier(){

					public boolean verify(String hostname,
							javax.net.ssl.SSLSession sslSession) {
						//return hostname.equals("localhost");
						return true;
					}
				});
		
		List<PestoIdP> idps = new LinkedList<>();
		idps.add(new PestoIdPRESTConnection("https://127.0.0.1:9933", "", 0));
		idps.add(new PestoIdPRESTConnection("https://127.0.0.1:9934", "", 1));
		idps.add(new PestoIdPRESTConnection("https://127.0.0.1:9935", "", 2));
		ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1), ((RSAPublicKey)idps.get(0).getCertificate()).getModulus());
		UserClient client = new PestoClient(idps, cryptoModule);


		Verifier verifier = new JWTVerifier(idps.get(0).getCertificate().getPublicKey());
		System.out.println("ready to run the test");
		testCreateTwoStepFlow(client, verifier);
	}

	
	@Ignore
	@Test
	public void testPestoDirect() throws Exception{
		
		int serverCount = 2;
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		KeyPair pair = keyGen.generateKeyPair();
		
		RSAPrivateCrtKey pk = (RSAPrivateCrtKey)pair.getPrivate();
		
		BigInteger phiN = pk.getPrimeP().subtract(BigInteger.ONE).multiply(pk.getPrimeQ().subtract(BigInteger.ONE));
		
		BigInteger d = pk.getPrivateExponent();
		
		Random rnd = new Random(1);
		BigInteger[] keyShares = new BigInteger[serverCount];
		BigInteger sum = BigInteger.ZERO;
		for(int i=0; i< serverCount-1; i++) {
			keyShares[i]=BigInteger.probablePrime(d.bitLength(), rnd).mod(phiN);
			sum = sum.add(keyShares[i]);
		}
		keyShares[serverCount-1] = d.subtract(sum);
		
		BigInteger[] oprfKeys = new BigInteger[serverCount];
		List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
		for(int i = 0; i< serverCount; i++) {
			oprfKeys[i] = new BigInteger(CommonCrypto.BITS_IN_GROUP+8*CommonCrypto.STATISTICAL_SEC_BYTES, rnd).mod(CommonCrypto.CURVE_ORDER);
			PestoDatabase db = new InMemoryPestoDatabase();
			PestoIdPImpl idp = null;
			
			
			try {
				idp = new PestoIdPImpl(db, identityProvers, new HashMap<>(), new SoftwareServerCryptoModule(new Random(i)));
			} catch(Exception e) {
				e.printStackTrace();
				
				fail("Failed to start IdP");
			}
			idps.add(idp);
		}
		
		List<Map<Integer, BigInteger>> rsaBlindings = new ArrayList<Map<Integer, BigInteger>>(serverCount);
		List<Map<Integer, BigInteger>> oprfBlindings = new ArrayList<Map<Integer, BigInteger>>(serverCount);
		for(int i=0; i< serverCount; i++) {
			rsaBlindings.add(new HashMap<>(serverCount));
			oprfBlindings.add(new HashMap<>(serverCount));
		}
		List<String> serverList = new ArrayList<>();
		for(int i=0; i< serverCount; i++) {
			serverList.add(""+i);
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

		for(int i = 0; i< serverCount; i++) {
			try {
				PestoIdPImpl idp = idps.get(i);
				List<PestoIdP> others = new ArrayList<PestoIdP>();
				others.addAll(idps);
				others.remove(idp);
				

				PABCConfigurationImpl config = new PABCConfigurationImpl();
				config.setServers(serverList);
				config.setKeyMaterial(new RSASharedKey(pk.getModulus(), keyShares[i], pk.getPublicExponent()));
				config.setRsaBlindings(rsaBlindings.get(i));
				config.setOprfBlindings(oprfBlindings.get(i));
				config.setOprfKey(oprfKeys[i]);
				config.setId(i);
				config.setAllowedTimeDifference(10000);
				Set<AttributeDefinition> dummyAttributes = new HashSet<>();
				dummyAttributes.add(new AttributeDefinitionString("id:dummy","dummy",0,10));
				config.setAttrDefinitions(dummyAttributes);
				config.setSeed("seed".getBytes());
				config.setLifetime(72000000);

				idp.setup("setup", config, others);

			} catch(Exception e) {
				fail("Failed to start IdP");
			}
		}

		ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1), ((RSAPublicKey)idps.get(0).getCertificate()).getModulus());
		UserClient client = new PestoClient(idps, cryptoModule);


		Verifier verifier = new JWTVerifier(idps.get(0).getCertificate().getPublicKey());
		System.out.println("ready to run the test");
		testCreateTwoStepFlow(client, verifier);
	}



	public void testCreateTwoStepFlow(UserClient client, Verifier verifier) throws CertificateEncodingException {
		try{
			client.createUser("user_2", "password");
		} catch(UserCreationFailedException e) {
			fail("Failed to create user");
		}
		
		try {
			UserCertificate userCertificate = new UserCertificate();
			userCertificate.setCert(certificate);
			client.addAttributes("user_2", "password", userCertificate, null, "NONE");
		} catch(AuthenticationFailedException e) {
			e.printStackTrace();
			fail("Failed to add user certificate: " + e);
		}

		try {
			CreditFile creditFile = new CreditFile();
			client.addAttributes("user_2", "password", creditFile, null, "NONE");
		} catch(AuthenticationFailedException e) {
			e.printStackTrace();
			fail("Failed to add creditfile: " + e);
		}

		try {
			TokenIdentityProof token = new TokenIdentityProof("random-string-value");
			client.addAttributes("user_2", "password", token, null, "NONE");
		} catch(AuthenticationFailedException e) {
			e.printStackTrace();
			fail("Failed to add user certificate: " + e);
		}
		
		//Create a policy to reveal

		String token;
		try {
			List<Predicate> predicates = new ArrayList<>();
			predicates.add(new Predicate("Name", Operation.REVEAL, null));
			Policy policy = new Policy(predicates, "some message");
			token = client.authenticate("user_1", "password", policy, null, "NONE");
			//Create proper verification
			assertThat(verifier.verify(token), is(true));
		} catch (AuthenticationFailedException e) {
			// TODO Auto-generated catch block
			fail();
		}

	}
	
	
	private Certificate loadCertificate(String path) {
		CertificateFactory cf = null;
		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e2) {
			e2.printStackTrace();
		}
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(new File(path));
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		}
		InputStream caInput = new BufferedInputStream(fis);
		Certificate ca = null;
		try {
			ca = cf.generateCertificate(caInput);
		} catch (CertificateException e) {
			e.printStackTrace();
		} finally {
			try {
				caInput.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return ca;
	}
}
