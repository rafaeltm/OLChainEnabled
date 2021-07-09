package eu.olympus.server.rest;

import eu.olympus.model.Attribute;
import eu.olympus.model.Authorization;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.PabcPublicParameters;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.AddMasterShare;
import eu.olympus.model.server.rest.AddPartialMFARequest;
import eu.olympus.model.server.rest.AddPartialSignatureRequest;
import eu.olympus.model.server.rest.SetKeyShare;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.util.multisign.MSverfKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.net.ssl.HostnameVerifier;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.miracl.core.BLS12461.ECP;


/**
 * REST wrapper for the IdP
 *
 */
public class PestoIdP2IdPRESTConnection implements PestoIdP {
	private String host;
	private Client client;
	private int id;
	private String authentication;

	/**
	 * Create a new mutual authenticated and encrypted TLS rest connections to an IdP
	 * @param url includes port, eg. http://127.0.0.1:9090
	 */
	public PestoIdP2IdPRESTConnection(String url, int id, String keyStore,
			String keyStorePW, String trustStore, String trustStorePW, String authentication) {
		this(url, id, authentication);

		Properties systemProps = System.getProperties();
		systemProps.put("javax.net.ssl.keyStorePassword", keyStorePW);
		systemProps.put("javax.net.ssl.keyStore", keyStore);
		systemProps.put("javax.net.ssl.trustStore", trustStore);
		systemProps.put("javax.net.ssl.trustStorePassword", trustStorePW);
		// Ensure that there is a certificate in the trust store for the webserver connecting
		HostnameVerifier verifier = new DefaultHostnameVerifier();
		javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(verifier);
	}

	public PestoIdP2IdPRESTConnection(String url, int id,
			String authentication) {
		this.id = id;
		this.authentication = "Bearer "+authentication;
		this.host = url+"/idp/";
	    this.client = ClientBuilder.newClient();
	}

	@Override
	public int getId() {
		return id;
	}

	@Override
	public void addPartialServerSignature(String ssid, byte[] signature) {
		AddPartialSignatureRequest request = new AddPartialSignatureRequest(ssid, Base64.encodeBase64String(signature));

		Response resp = client.target(host+PestoRESTEndpoints.ADD_PARTIAL_SIGNATURE).request()
			.header("Authorization", authentication)
			.post(Entity.entity(request, MediaType.APPLICATION_JSON));
	}

	@Override
	public void addPartialMFASecret(String ssid, String secret, String type) {
		AddPartialMFARequest request = new AddPartialMFARequest(ssid, secret, type);
		client.target(host+PestoRESTEndpoints.ADD_PARTIAL_MFA_SECRET).request()
			.header("Authorization", authentication)
			.post(Entity.entity(request, MediaType.APPLICATION_JSON));
	}
	
	@Override
	public void addMasterShare(String newSsid, byte[] newShare) {
		AddMasterShare request = new AddMasterShare(newSsid, Base64.encodeBase64String(newShare));
		Response resp = client.target(host+PestoRESTEndpoints.ADD_MASTER_SHARE).request()
			.header("Authorization", authentication)
			.post(Entity.entity(request, MediaType.APPLICATION_JSON));
		String newCookie = resp.getHeaderString("Authorization");
		authentication = newCookie;
	}

	@Override
	public void setKeyShare(int id, byte[] newShare) {
		SetKeyShare request = new SetKeyShare(id, Base64.encodeBase64String(newShare));
		client.target(host+PestoRESTEndpoints.SET_KEY_SHARE).request()
			.header("Authorization", authentication)
			.post(Entity.entity(request, MediaType.APPLICATION_JSON));
	}

	@Override
	public Certificate getCertificate() {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public byte[] finishRegistration(String username, byte[] cookie, PublicKey publicKey, byte[] signature,
			long salt, String idProof) throws Exception {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public String authenticate(String username, byte[] cookie, long salt, byte[] signature, Policy policy)
			throws Exception {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public String getCredentialShare(String username, byte[] cookie, long salt, byte[] signature, long timestamp)
			throws Exception {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public MSverfKey getPabcPublicKeyShare() {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public PabcPublicParameters getPabcPublicParam() {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public boolean addAttributes(String username, byte[] cookie, long salt, byte[] signature, String idProof) {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public Map<String, Attribute> getAllAttributes(String username, byte[] cookie, long salt, byte[] signature) {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public boolean deleteAttributes(String username, byte[] cookie, long salt, byte[] signature,
			List<String> attributes) {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public boolean deleteAccount(String username, byte[] cookie, long salt, byte[] signature) {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public byte[] changePassword(String username, byte[] cookie, PublicKey publicKey, byte[] oldSignature,
			byte[] newSignature, long salt) throws Exception {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public boolean startRefresh() {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public boolean confirmMFA(String username, byte[] cookie, long salt, String token, String type, byte[] signature) {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public String requestMFA(String username, byte[] cookie, long salt, String type, byte[] signature) {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public boolean removeMFA(String username, byte[] cookie, long salt, String token, String type, byte[] signature) {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public OPRFResponse performOPRF(String ssid, String username, ECP x, String mfaToken, String mfaType)
			throws UserCreationFailedException {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public void addSession(String cookie, Authorization authorization) {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public void validateSession(String cookie, List<Role> requestedRoles) throws AuthenticationFailedException {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}

	@Override
	public String refreshCookie(String cookie) {
		throw new UnsupportedOperationException("Not a supported call by a partial IdP");
	}
}
