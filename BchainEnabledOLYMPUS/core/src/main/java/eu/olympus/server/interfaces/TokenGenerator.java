package eu.olympus.server.interfaces;

import eu.olympus.model.Attribute;

import java.security.PublicKey;
import java.util.Map;

/**
 * Generic interface for producing access tokens or credentials.
 *
 */
public interface TokenGenerator {

	/**
	 * Get the combined public key material for the vIdP, used to
	 * validate tokens issued by the vIdP.
	 * @return A public key 
	 */
	public PublicKey getPublicKey();

	/**
	 * Produce a signed access token or credential.
	 * @param assertions The attributes that should be contained in
	 * the token or credential 
	 * @return A string encoding of the token or credential.
	 * @throws Exception If something goes wrong.
	 */
	public String generateToken(Map<String, Attribute> assertions) throws Exception;
	
}
