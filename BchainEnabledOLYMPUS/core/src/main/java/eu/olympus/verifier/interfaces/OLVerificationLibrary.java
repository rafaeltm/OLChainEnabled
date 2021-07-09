package eu.olympus.verifier.interfaces;

import eu.olympus.model.Attribute;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.util.Pair;
import eu.olympus.util.rangeProof.RangePredicateToken;
import eu.olympus.verifier.OLVerificationLibraryResult;

import java.util.Map;
import java.util.Set;


public interface OLVerificationLibrary {


    /**
     * Parse a credentialSubject (coming from W3CSerializationLibrary) to extract the relevant information (revealed attributes
     * and range predicates).
     * @param subject Credential subject
     * @return A pair where the first member is the map of attributes revealed and the second the (range) predicates
     * included in the subject
     */
    Pair<Map<String, Attribute>,Set<Predicate>> parseCredentialSubject(Map<String, Object> subject);

    /**
     * Verify a OlPsDerivedProof, which in particular translates to a PS zero-knowledge token that reveals a subset of attributes
     * @param token The encoded form of the PsZkToken
     * @param revealedAttributes The map of attributes that were revealed in the presentation
     * @param nonce The nonce used for creating the zero-knowledge signature
     * @param epoch The epoch (corresponding to the PS credential)
     * @return
     */
    OLVerificationLibraryResult verifyOlPsDerivedProof(String token, Map<String, Attribute> revealedAttributes, String nonce, long epoch);

    /**
     * Verify a OlPsDerivedProofRange, which in particular translates to a PS zero-knowledge token that reveals a subset of attributes and links
     * a set of range proofs to the credential. Validity of both the zk/link token and individual range proofs are verified.
     * @param token Encoded form of the PsZkTokenModified
     * @param revealedAttributes The map of attributes that were revealed in the presentation
     * @param rangeTokens Map of RangePredicateTokens, used for proving/verifying the individual range predicates
     * @param rangePredicates The range predicates used in the presentation
     * @param nonce The nonce used for creating the zero-knowledge signature and as a seed for range proofs
     * @param epoch The epoch (corresponding to the PS credential)
     * @return
     */
    OLVerificationLibraryResult verifyOlPsDerivedProofRange(String token, Map<String, Attribute> revealedAttributes, Map<String, RangePredicateToken> rangeTokens, Set<Predicate> rangePredicates, String nonce, long epoch);
}
