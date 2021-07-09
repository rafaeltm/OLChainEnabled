package eu.olympus.server;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.fabric.FabricConnection;
import eu.olympus.server.interfaces.PestoIdP;

import java.net.InetAddress;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import eu.olympus.model.Attribute;
import eu.olympus.model.Authorization;
import eu.olympus.model.KeyShares;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.PabcPublicParameters;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PABCConfiguration;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.interfaces.Storage;
import eu.olympus.server.rest.CommonRESTEndpoints;
import eu.olympus.server.rest.Role;
import eu.olympus.server.storage.InMemoryKeyDB;
import eu.olympus.util.multisign.MSverfKey;
import java.security.cert.Certificate;

import org.miracl.core.BLS12461.ECP;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PestoIdPImpl implements PestoIdP {

	private int id;
	private ServerCryptoModule cryptoModule;
	private PestoAuthenticationHandler authenticationHandler;
	private ThresholdRSAJWTTokenGenerator tokenGenerator;
	private ThresholdPSSharesGenerator sharesGenerator;
	private Certificate cert;
	//private DIDWrapper didWrapper = DIDWrapper.getDIDWrapperInstance();
	int nServers;
	private static Logger logger = LoggerFactory.getLogger(PestoIdPImpl.class);
		
	public PestoIdPImpl(Storage database, List<IdentityProver> identityProvers, Map<String, MFAAuthenticator> authenticators, ServerCryptoModule cryptoModule) throws Exception {
		this.cryptoModule = cryptoModule;
		authenticationHandler = new PestoAuthenticationHandler(database, cryptoModule, new InMemoryKeyDB(), authenticators);
		tokenGenerator = new ThresholdRSAJWTTokenGenerator(cryptoModule);
		sharesGenerator = new ThresholdPSSharesGenerator(database, cryptoModule.getBytes(57), id);
		if (identityProvers != null) {
			for (IdentityProver idProver : identityProvers) {
				authenticationHandler.addIdentityProver(idProver);
			}
		}
	}

	public boolean setup(String ssid,
			PABCConfiguration pabcConfiguration,
			List<? extends PestoIdP> servers) {
		try {
			KeyShares master = new KeyShares(pabcConfiguration.getKeyMaterial(), pabcConfiguration.getRsaBlindings(),
					pabcConfiguration.getOprfKey(),pabcConfiguration.getOprfBlindings());
			boolean res = authenticationHandler.setup(ssid, master, pabcConfiguration.getLocalKeyShare(), pabcConfiguration.getRemoteShares(), pabcConfiguration.getId(),
					pabcConfiguration.getAllowedTimeDifference(), pabcConfiguration.getWaitTime(), pabcConfiguration.getSessionLength(), servers);
			id = pabcConfiguration.getId();
			cert = pabcConfiguration.getCert();
			sharesGenerator.setup(pabcConfiguration);
			nServers=servers.size()+1;

			if(pabcConfiguration.getUseBchain()){
				ObjectMapper mapper = new ObjectMapper();
				String idpId = pabcConfiguration.didSetup() + "OL-Partial-IdP:" + pabcConfiguration.getId() + ":"+pabcConfiguration.getVidpName();
				String vIdPID = pabcConfiguration.didSetup() + "OL-vIdP" + ":"+pabcConfiguration.getVidpName();
				String schemaID = pabcConfiguration.didSetup() + "OL-PublicParameters:Scheme-"+pabcConfiguration.getVidpName();

				FabricConnection.addOrUpdateIDP(idpId,
						"" + InetAddress.getLocalHost().getHostAddress() + ":" + pabcConfiguration.getPort(),
						Base64.encodeBase64String(sharesGenerator.getVerificationKeyShare().getEncoded()), vIdPID);
				FabricConnection.addOrUpdateCredentialSchema(mapper.writeValueAsString(sharesGenerator.getPublicParam()), schemaID, idpId);
			}
			return res;
		} catch(Exception e) {
			return false;
		}
	}
	
	@Override
	public void addSession(String cookie, Authorization authorization) {
		this.authenticationHandler.storeAuthorization(cookie, authorization);
	}

	@Override
	public void validateSession(String cookie, List<Role> requestedRole) throws AuthenticationFailedException {
		this.authenticationHandler.validateSession(cookie, requestedRole);
	}

	public OPRFResponse performOPRF(String ssid, String username, ECP x, String cookie) throws UserCreationFailedException, AuthenticationFailedException {
		validateSession(cookie, Arrays.asList(Role.USER));
		return authenticationHandler.performOPRF(ssid, username, x, cookie);
	}

	@Override
	public OPRFResponse performOPRF(String ssid, String username, ECP x, String mfaToken, String mfaType)
			throws UserCreationFailedException, AuthenticationFailedException {
		return authenticationHandler.performOPRF(ssid, username, x, mfaToken, mfaType);
	}
	
	public boolean startRefresh() {
		return authenticationHandler.startRefresh();
	}

	public void addMasterShare(String newSsid, byte[] share) {
		authenticationHandler.addMasterShare(newSsid, share);
	}

	public void setKeyShare(int id, byte[] newShare) {
		authenticationHandler.setKeyShare(id, newShare);
	}

	public void addPartialServerSignature(String ssid, byte[] signature) {
		authenticationHandler.addPartialServerSignature(ssid, signature);
	}

	public void addPartialMFASecret(String ssid, String secret, String type) {
		authenticationHandler.addPartialMFASecret(ssid, secret, type);
	}
	
	@Override
	public byte[] finishRegistration(String username, byte[] cookie, PublicKey publicKey, byte[] signature, long salt, String idProof) throws Exception {
		validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
		return authenticationHandler.finishRegistration(username, cookie, publicKey, signature, salt, idProof);
	}
	
	@Override
	public String authenticate(String username, byte[] cookie, long salt, byte[] signature, Policy policy) throws Exception {
		validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
		boolean authenticated = authenticationHandler.validateUsernameAndSignature(username, cookie, salt, signature, CommonRESTEndpoints.AUTHENTICATE);
		if(authenticated) {
			try{
				Map<String, Attribute> assertions = authenticationHandler
						.validateAssertions(username, policy);
				return tokenGenerator.generateToken(assertions);
			} catch(Exception e) {
				throw new AuthenticationFailedException("Failed : Could not produce a token");
			}
		}
		throw new AuthenticationFailedException("Failed : User failed authentication");
	}

	@Override
	public String getCredentialShare(String username, byte[] cookie, long salt, byte[] signature, long timestamp) throws Exception {
		validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
		boolean authenticated = authenticationHandler.validateUsernameAndSignature(username, cookie, salt, signature, CommonRESTEndpoints.AUTHENTICATE);
		if(authenticated) {
			return sharesGenerator.createCredentialShare(username,timestamp).toJSONString();
		}
		throw new AuthenticationFailedException("Failed : User failed authentication");
	}

	public MSverfKey getPabcPublicKeyShare(){
		return sharesGenerator.getVerificationKeyShare();
	}

	public PabcPublicParameters getPabcPublicParam(){
		return sharesGenerator.getPublicParam();
	}

	@Override
	public Certificate getCertificate() {
		return cert;
	}

	@Override
	public int getId() {
		return id;
	}

	//public String getDIDDocument() {
	//	return this.did.toJson(true);
	//}
	//public String getDid() {
	//	return did.getId().toString();
	//}

	@Override
	public boolean addAttributes(String username, byte[] cookie, long salt, byte[] signature, String idProof) throws AuthenticationFailedException {
		validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
		boolean authenticated = authenticationHandler.validateUsernameAndSignature(username, cookie, salt, signature, CommonRESTEndpoints.ADD_ATTRIBUTES+idProof);
		try {
			if(authenticated) {
				this.authenticationHandler.addAttributes(username, idProof);
				return true;
			}
		} catch(Exception e) {
			logger.info("PESTO_IMP: " + e.getMessage());
		}
		throw new AuthenticationFailedException("Failed : User failed authentication");
	}

	@Override
	public Map<String, Attribute> getAllAttributes(String username, byte[] cookie, long salt, byte[] signature) throws AuthenticationFailedException {
		validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
		boolean authenticated = authenticationHandler.validateUsernameAndSignature(username, cookie, salt, signature, CommonRESTEndpoints.GET_ALL_ATTRIBUTES);
		if(authenticated) {
			Map<String, Attribute> assertions = authenticationHandler
					.getAllAssertions(username);
			return assertions;
		}
		throw new AuthenticationFailedException("Failed : User failed authentication");
	}

	@Override
	public boolean deleteAttributes(String username, byte[] cookie, long salt, byte[] signature, List<String> attributes) throws AuthenticationFailedException {
		validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
		boolean authenticated = authenticationHandler.validateUsernameAndSignature(username, cookie, salt, signature, CommonRESTEndpoints.DELETE_ATTRIBUTES);
		if(authenticated) {
			authenticationHandler.deleteAttributes(username, attributes);
			return true;
		}
		throw new AuthenticationFailedException("Failed : User failed authentication");
	}

	@Override
	public boolean deleteAccount(String username, byte[] cookie, long salt, byte[] signature) throws AuthenticationFailedException {
		validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
		boolean authenticated = authenticationHandler.validateUsernameAndSignature(username, cookie, salt, signature, CommonRESTEndpoints.DELETE_ACCOUNT);
		if(authenticated) {
			authenticationHandler.deleteAccount(username);
			return true;
		}
		throw new AuthenticationFailedException("Failed : User failed authentication");
	}

	@Override
	public byte[] changePassword(String username, byte[] cookie, PublicKey publicKey, byte[] oldSignature, byte[] newSignature, long salt) throws Exception {
		validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
		return authenticationHandler.changePassword(username, cookie, publicKey, oldSignature, newSignature, salt);
	}

	@Override
	public String requestMFA(String username, byte[] cookie, long salt, String type, byte[] signature) throws AuthenticationFailedException{
		validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
		try {
			boolean authenticated = authenticationHandler.validateUsernameAndSignature(username, cookie, salt, signature, CommonRESTEndpoints.REQUEST_MFA);
			if(authenticated) {
				return authenticationHandler.requestMFASecret(username, type);
			}
		}catch (Exception e) {
		}
		throw new AuthenticationFailedException("Authentication failed");
	}
	
	@Override
	public boolean confirmMFA(String username, byte[] cookie, long salt, String token, String type, byte[] signature) throws AuthenticationFailedException {
		validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
		boolean authenticated = authenticationHandler.validateUsernameAndSignature(username, cookie, salt, signature, CommonRESTEndpoints.CONFIRM_MFA);
		if(authenticated) {
			return authenticationHandler.activateMFA(username, token, type);
		}
		throw new AuthenticationFailedException("Failed : User failed authentication");
	}

	@Override
	public boolean removeMFA(String username, byte[] cookie, long salt, String token, String type, byte[] signature) throws AuthenticationFailedException {
		validateSession(Base64.encodeBase64String(cookie), Arrays.asList(Role.USER));
		boolean authenticated = authenticationHandler.validateUsernameAndSignature(username, cookie, salt, signature, CommonRESTEndpoints.REMOVE_MFA);
		if(authenticated) {
			return authenticationHandler.deleteMFA(username, token, type);
		}
		throw new AuthenticationFailedException("Failed : User failed authentication");
	}

	@Override
	public String refreshCookie(String cookie) {
		return authenticationHandler.refreshCookie(cookie);
	}

	//TODO: Generated keypair is not refreshed during "TestCompleteFlow": Check.
//	private void generateDIDDocument(int id, String endpoint) {
//		Service test = DIDWrapper.buildService("Olympus-IdP", endpoint);
//		VerificationMethod verf = DIDWrapper.buildVerificationMethod(URI.create("did:olympus-idp:" + id),
//				"key" + id,
//				Base58.newInstance().encode(didWrapper.getPublicKey().getEncoded()));
//
//		this.didDocument = DIDWrapper.generateDIDDocument(URI.create("did:olympus-idp:" + id), test, verf);
//
//		System.out.println(this.didDocument.toJson());
//	}
}
