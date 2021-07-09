package eu.olympus.usecase.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.model.Authorization;
import eu.olympus.model.PABCConfigurationImpl;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.rest.PestoIdP2IdPRESTConnection;
import eu.olympus.server.rest.PestoIdPServlet;
import eu.olympus.server.rest.RESTIdPServer;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import eu.olympus.usecase.server.identityprovers.SignIdentityProver;
import eu.olympus.util.keyManagement.CertificateUtil;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import java.io.File;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

import static eu.olympus.util.CommonCrypto.PUBLIC_EXPONENT;

public class RunServer {
	public static void main(String[] args) throws Exception {
		ObjectMapper mapper = new ObjectMapper();
		PABCConfigurationImpl configuration = mapper.readValue(new File(args[0]), PABCConfigurationImpl.class);

		List<PestoIdP> others = new ArrayList<PestoIdP>();
		for (String s : configuration.getServers()) {
			others.add(new PestoIdP2IdPRESTConnection(s, configuration.getId(), configuration.getKeyStorePath(), configuration.getKeyStorePassword(),
					configuration.getTrustStorePath(), configuration.getTrustStorePassword(), configuration.getMyAuthorizationCookies()));
		}

		RSAPublicKeySpec spec = new RSAPublicKeySpec(configuration.getKeyMaterial().getModulus(), PUBLIC_EXPONENT);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		RSAPublicKey pubKey = (RSAPublicKey) factory.generatePublic(spec);

		RSAPrivateKeySpec pSpec = new RSAPrivateKeySpec(configuration.getKeyMaterial().getModulus(), configuration.getKeyMaterial().getPrivateKey());
		RSAPrivateKey pkey = (RSAPrivateKey) factory.generatePrivate(pSpec);

		PKCS10CertificationRequest csr = CertificateUtil.makeCSR(pkey, pubKey, "CN=127.0.0.1,O=Olympus,OU=www.olympus-project.eu,C=EU");
		configuration.setCert(CertificateUtil.makeSelfSignedCert(pkey, csr));

		//Setup databases
		PestoDatabase db = new InMemoryPestoDatabase();

		//Setup identity provers
		List<IdentityProver> identityProvers = new LinkedList<IdentityProver>();
		identityProvers.add(new SignIdentityProver(db));

		ServerCryptoModule cryptoModule = new SoftwareServerCryptoModule(new SecureRandom());

		List<String> types = new ArrayList<>(1);
		types.add(PestoIdPServlet.class.getCanonicalName());

		//Setup the IdP.
		PestoIdPImpl idp = null;
		idp = new PestoIdPImpl(db, identityProvers, new HashMap<>(), cryptoModule);
		idp.setup("ssid", configuration, others);
		for (String cookie : configuration.getAuthorizationCookies().keySet()) {
			Authorization authorization = configuration.getAuthorizationCookies().get(cookie);
			authorization.setExpiration(System.currentTimeMillis() + 604800000); //valid for one week
			idp.addSession(cookie, authorization);
		}

		RESTIdPServer restServer = new RESTIdPServer();
		restServer.setIdP(idp);
		restServer.start(configuration.getPort(), types,
				configuration.getTlsPort(),
				configuration.getKeyStorePath(),
				configuration.getKeyStorePassword(),
				configuration.getTrustStorePassword());
	}
}