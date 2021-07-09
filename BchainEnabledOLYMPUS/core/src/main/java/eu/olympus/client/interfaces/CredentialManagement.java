package eu.olympus.client.interfaces;

import VCModel.VerifiableCredential;
import VCModel.VerifiablePresentation;
import eu.olympus.model.Policy;
import java.util.Map;

public interface CredentialManagement {


  //  /**
  //   * Combine credential shares in a full credential
  //   * @param credentialShares Credential shares received from the servers.
  //   * @return True if the credential was successfully created and false if not.
  //   */
  //  boolean combineAndStoreCredential(Map<Integer,PSCredential> credentialShares);

    /**
     * Generate zero knowledge presentation token for a given policy.
     * @param policy Policy that determines which attributes and properties will have to be revealed in the presentation token,
     *        as well as the message that will be signed.
     * @return A presentation token conforming to the desired policy.
     */
    VerifiablePresentation generatePresentationToken(Policy policy);

    /**
     * Combine credential shares in a full credential and use it to derive a presentation token.
     * If boolean storage is set, also store the credential
     * @param credentialShares Credential shares received from the servers.
     * @param policy Policy that determines which attributes and properties will have to be revealed in the presentation token,
     *        as well as the message that will be signed.
     * @return A presentation token conforming to the desired policy.
     */
    VerifiablePresentation combineAndGeneratePresentationToken(Map<Integer, VerifiableCredential> credentialShares, Policy policy);
    /**
     * Check if there is a valid stored credential for presentation token generation
     * @return True if there is a valid credential, false otherwise
     */
    boolean checkStoredCredential();

    /**
     * Removes stored credentials.
     */
    void clearCredential();

}
