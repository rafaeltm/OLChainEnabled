package eu.olympus.server.interfaces;

import eu.olympus.model.Attribute;
import eu.olympus.model.Authorization;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.PabcPublicParameters;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.server.rest.Role;
import eu.olympus.util.multisign.MSverfKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import org.miracl.core.BLS12461.ECP;

public interface PestoIdP extends VirtualIdP {
	public OPRFResponse performOPRF(String ssid, String username, ECP x, String mfaToken, String mfaType) throws UserCreationFailedException, AuthenticationFailedException;

	public boolean startRefresh();
	
	public void addMasterShare(String newSsid, byte[] share);
	
	public void setKeyShare(int id, byte[] newShare);
	
	public void addPartialServerSignature(String ssid, byte[] signature);
	
	public void addPartialMFASecret(String ssid, String secret, String type);
	
	public byte[] finishRegistration(String username, byte[] cookie, PublicKey publicKey, byte[] signature, long salt, String idProof) throws Exception;
	
	public String authenticate(String username, byte[] cookie, long salt, byte[] signature, Policy policy) throws Exception;
	
	public String getCredentialShare(String username, byte[] cookie, long salt, byte[] signature, long timestamp) throws Exception;
	
	public MSverfKey getPabcPublicKeyShare();
	
	public PabcPublicParameters getPabcPublicParam();
	
	public boolean addAttributes(String username, byte[] cookie, long salt, byte[] signature, String idProof) throws AuthenticationFailedException;
	
	public Map<String, Attribute> getAllAttributes(String username, byte[] cookie, long salt, byte[] signature) throws AuthenticationFailedException;
	
	public boolean deleteAttributes(String username, byte[] cookie, long salt, byte[] signature, List<String> attributes) throws AuthenticationFailedException;
	
	public boolean deleteAccount(String username, byte[] cookie, long salt, byte[] signature) throws AuthenticationFailedException;
	
	public byte[] changePassword(String username, byte[] cookie, PublicKey publicKey, byte[] oldSignature, byte[] newSignature, long salt) throws Exception;

	public boolean confirmMFA(String username, byte[] cookie, long salt, String token, String type, byte[] signature) throws AuthenticationFailedException;
	
	public String requestMFA(String username, byte[] cookie, long salt, String type, byte[] signature) throws AuthenticationFailedException;

	/**
	 * Removes a MFA type. The MFA MUST exist and be active for the removal to be successful.
	 * Furthermore, this can only be done after MFA authentication and requires a new MFA token be verified.
	 * Returns true if successful and otherwise false. In case false is returned, the MFA remains active.
	 * @param username The username for which the MFA must be removed
	 * @param cookie The active cookie for the given server
	 * @param salt The nonce used in the signature that authenticates the user's password
	 * @param token A MFA token valid for the MFA to be removed
	 * @param type The type of MFA to remove
	 * @param signature A signature on the request
	 * @return True if the MFA was successfully removed
	 */
	public boolean removeMFA(String username, byte[] cookie, long salt, String token, String type, byte[] signature) throws AuthenticationFailedException;

	/**
	 * Add a session cookie to storage. This is an administrative method, used to manually
	 * grant access to other partial-IdP instances during configuration. 
	 * @param cookie The cookie to add
	 * @param authorization The attached Authorization
	 */
	public void addSession(String cookie, Authorization authorization);

	/**
	 * Verifies that AT LEAST ONE of the requestedRoles are granted to the user with the given cookie.
	 * @param cookie
	 * @param requestedRoles
	 * @throws AuthenticationFailedException
	 */
	public void validateSession(String cookie, List<Role> requestedRoles) throws AuthenticationFailedException;

	/**
	 * Replaces an existing session with a fresh generated one. Roles are transfered from the
	 * existing cookie.
	 * @param cookie The existing cookie
	 * @return A new cookie
	 */
	public String refreshCookie(String cookie);
}
