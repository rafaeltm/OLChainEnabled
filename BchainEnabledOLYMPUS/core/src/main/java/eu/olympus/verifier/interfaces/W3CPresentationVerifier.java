package eu.olympus.verifier.interfaces;

import eu.olympus.model.Policy;
import eu.olympus.verifier.W3CVerificationResult;

public interface W3CPresentationVerifier {

    /**
     * Verify if a W3C Presentation is valid
     * @param token Serialized W3C presentation.
     * @param policy Policy it needs to comply to, including message signed.
     * @return W3CVerificationResult.VALID if the presentation is valid and fulfills the policy. A description of the error otherwise.
     */
    W3CVerificationResult verifyPresentationToken(String token, Policy policy);

}
