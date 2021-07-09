package eu.olympus.server;

import eu.olympus.model.Attribute;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.interfaces.Storage;
import eu.olympus.server.storage.InMemoryKeyDB;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;

public class DistributedRSAIdP extends AbstractPasswordIdP {
	private final int id;
	private final ThresholdRSAJWTTokenGenerator tokenGenerator;
	private final Certificate certificate;
	
	public DistributedRSAIdP(Storage database, int id, List<IdentityProver> idProvers,
			ServerCryptoModule cryptoModule,
			Map<String, MFAAuthenticator> mfaAuthenticators, Certificate certificate) throws Exception{
		this.id = id;
		authenticationHandler = new PasswordHandler(database, cryptoModule, new InMemoryKeyDB(), mfaAuthenticators);
		for(IdentityProver idProver: idProvers) {
			authenticationHandler.addIdentityProver(idProver);
		}
		tokenGenerator = new ThresholdRSAJWTTokenGenerator(cryptoModule);
		this.certificate = certificate;
	}

	public String authenticate(String username, byte[] cookie, Policy policy) throws AuthenticationFailedException {
		if(validateSession(Base64.encodeBase64String(cookie))) {
			try{
				Map<String, Attribute> assertions = authenticationHandler
						.validateAssertions(username, policy);
				return tokenGenerator.generateToken(assertions);
			} catch(Exception e) {
				return "Failed : IdP not initialized";
			}
		}
		throw new AuthenticationFailedException("Authentication failed");
	}

	@Override
	public Certificate getCertificate() {
		return certificate;
	}

	@Override
	public int getId() {
		return id;
	}
}
