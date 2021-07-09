package eu.olympus.client;

import VCModel.Proof;
import VCModel.Verifiable;
import VCModel.VerifiableCredential;
import VCModel.VerifiablePresentation;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.model.PSCredential;
import eu.olympus.model.Policy;
import eu.olympus.model.PresentationToken;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.rest.CommonRESTEndpoints;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Future;


public class PabcClient extends PestoAuthClient {

	private CredentialManagement credentialManagement;
	
	// Maybe instead of a list (and derive the integer identifier from the inferred order) a map with identifiers.
	public PabcClient(List<? extends PestoIdP> servers, CredentialManagement credentialManagement, ClientCryptoModule cryptoModule) throws NoSuchAlgorithmException {
		super(servers, cryptoModule);
		this.credentialManagement = credentialManagement;
	}

	@Override
	public String authenticate(String username, String password, Policy policy, String token, String type) {
		if(!credentialManagement.checkStoredCredential()){ //If no stored credential, get a new one
			try {
				ensureActiveSession(username, password, token, type);
				long salt = getFreshSalt();
				byte[][] signature = getSignedNonceAndUid(username, salt,
						CommonRESTEndpoints.AUTHENTICATE);
				Map<Integer,VerifiableCredential> partialCredentials = new HashMap<>();
				Map<Integer,Future<String>> authentications = new HashMap<>();
				for (Integer i: servers.keySet()){
					authentications.put(i,executorService.submit(() -> servers.get(i).getCredentialShare(username, cookies
							.get(i), salt, signature[i], salt)));
				}
				for(Integer iresp : authentications.keySet()) {
						VerifiableCredential reconstructed = new VerifiableCredential(Verifiable.getJSONMap(authentications.get(iresp).get()));
						partialCredentials.put(iresp, reconstructed);
				}

				VerifiablePresentation vp = new VerifiablePresentation(
						Verifiable.getJSONMap(
								credentialManagement.combineAndGeneratePresentationToken(partialCredentials, policy).toJSONString()));
				return vp != null ? vp.toJSONString(): "Failed";
			} catch(Exception e) {
				e.printStackTrace();
				return "Failed";
			}
		}
		return credentialManagement.generatePresentationToken(policy).toJSONString();
	}


	@Override
	public void clearSession() {
		super.clearSession();
		credentialManagement.clearCredential();
	}
}
