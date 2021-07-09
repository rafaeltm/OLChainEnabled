package eu.olympus.verifier;

import VCModel.Proof;
import VCModel.Verifiable;
import VCModel.VerifiableCredential;
import VCModel.VerifiablePresentation;
import eu.olympus.model.Attribute;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.util.Pair;
import eu.olympus.util.Util;
import eu.olympus.util.W3CSerializationUtil;
import eu.olympus.util.rangeProof.RangePredicateToken;
import eu.olympus.verifier.interfaces.OLVerificationLibrary;
import eu.olympus.verifier.interfaces.W3CPresentationVerifier;

import javax.validation.constraints.NotNull;
import java.util.*;

public class W3CPresentationVerifierOL implements W3CPresentationVerifier {

    private OLVerificationLibrary verificationLibrary;

    public W3CPresentationVerifierOL(@NotNull OLVerificationLibrary verificationLibrary) {
        this.verificationLibrary = verificationLibrary;
    }

    @Override
    public W3CVerificationResult verifyPresentationToken(String token, Policy policy) {
        VerifiablePresentation reconstructedPresentation = null;
        try {
            reconstructedPresentation = new VerifiablePresentation(Verifiable.getJSONMap(token));
        } catch (Exception e) {
            return W3CVerificationResult.INVALID_TOKEN;
        }
        Date now=new Date(System.currentTimeMillis());
        // Here, a "complete" W3C verifier would check valid syntax of the JSON using @context and "validation credentialSchema"
        // In this "mock W3C verifier", we will simply parse needed fields and if something is not present/wrong, return INVALID_TOKEN
        //Extract and check (further check later when checking proof may be needed) Presentation expiration date
        Date presExpirationDate=reconstructedPresentation.getExpirationDate();
        if(presExpirationDate==null)
            return W3CVerificationResult.INVALID_TOKEN;
        else if(presExpirationDate.before(now))
            return W3CVerificationResult.BAD_TIMESTAMP;
        // Extract credential (we will work with only one credential in a presentation for now. If we want to support more
        // from this point we can simply do a loop that should not need heavy modifications
        List<VerifiableCredential> verifiableCredentials=reconstructedPresentation.getVCCredentials();
        if(verifiableCredentials.isEmpty())
            return W3CVerificationResult.INVALID_TOKEN;
        VerifiableCredential cred=verifiableCredentials.get(0); // If we want to support multiple credentials included in a presentation we would need to do a loop with following code
        // Credential expiration date (may involve epoch or not)
        Date credExpirationDate=cred.getExpirationDate();
        if(credExpirationDate==null)
            return W3CVerificationResult.INVALID_TOKEN;
        if(credExpirationDate.before(now))
            return W3CVerificationResult.BAD_TIMESTAMP;
        // Extract revealed attributes and predicates (from credentialSubject). Probably call "serialization binary" here
        // IMPORTANT! In serialized presentation attribute names will be in the short form, when we extract them we will
        // consider the attribute id (which would be used in crypto and policies)
        Map<String, Object> subject=cred.obtainCredentialSubject();
        Pair<Map<String,Attribute>,Set<Predicate>> subjectExtractedInfo=verificationLibrary.parseCredentialSubject(subject);
        if (subjectExtractedInfo==null)
            return W3CVerificationResult.INVALID_ATTRIBUTES;
        Map<String, Attribute> revealedAttributes= subjectExtractedInfo.getFirst();
        Set<Predicate> predicatesInSubject= subjectExtractedInfo.getSecond();
        // Check with policy predicates
        Set<String> attributesToReveal = new HashSet<>();
        Set<Predicate> rangePredicates=new HashSet<>();
        for(Predicate p: policy.getPredicates()) {
            if(p.getOperation() == Operation.REVEAL) {
                attributesToReveal.add(p.getAttributeName());
            } else if (p.getOperation() == Operation.INRANGE || p.getOperation() == Operation.GREATERTHAN || p.getOperation() == Operation.LESSTHAN) {
                rangePredicates.add(p);
            } else {
                return W3CVerificationResult.INVALID_POLICY;
            }
        }
        if(!revealedAttributes.keySet().containsAll(attributesToReveal))
            return W3CVerificationResult.POLICY_NOT_FULFILLED;
        if(!predicatesInSubject.containsAll(rangePredicates))
            return W3CVerificationResult.POLICY_NOT_FULFILLED;
        //Extract proof and relevant fields (if no range proofs present has to be OLPSDerivedProof, else OlPSDerivedProofWithRange)
        Proof proof=cred.obtainVCProof();
        if(proof==null)
            return W3CVerificationResult.INVALID_TOKEN;
        Object type=proof.getType();
        if(!(type instanceof String))
            return W3CVerificationResult.INVALID_TOKEN;
        Object epoch=proof.getEpoch();
        if(!(epoch instanceof Long) || !(epoch.equals(credExpirationDate.getTime())))
            return W3CVerificationResult.INVALID_TOKEN;
        Object nonce=proof.getNonce();
        if(!(nonce instanceof String)) //TODO Check relationship between nonce and presentation expiration date if we end up using that method
            return W3CVerificationResult.INVALID_TOKEN;
        if (!(nonce.equals(policy.getPolicyId())))
            return W3CVerificationResult.POLICY_NOT_FULFILLED;
        //Use OlVerifier as needed
        switch ((String) type){
            case "OlPsDerivedProof":
                if (!rangePredicates.isEmpty())
                    return W3CVerificationResult.INVALID_SIGNATURE;
                return verifyOlPsDerivedProof(proof,revealedAttributes,(String) nonce, (Long) epoch);
            case "OlPsDerivedProofRange":
                if (rangePredicates.isEmpty())
                    return W3CVerificationResult.INVALID_SIGNATURE;
                return verifyOlPsDerivedProofRange(proof,revealedAttributes,rangePredicates,(String) nonce, (Long) epoch);
            default:
                return W3CVerificationResult.INVALID_TOKEN;
        }
    }

    private W3CVerificationResult verifyOlPsDerivedProof(Proof proof, Map<String, Attribute> revealedAttributes, String nonce, long epoch) {
        Object pv=proof.getProofValue();
        if(!(pv instanceof String))
            return W3CVerificationResult.INVALID_TOKEN;
        if (verificationLibrary.verifyOlPsDerivedProof((String) pv, revealedAttributes, nonce, epoch) == OLVerificationLibraryResult.VALID) {
            return W3CVerificationResult.VALID;
        } //case INVALID_ATTRIBUTES: return W3CVerificationResult.INVALID_ATTRIBUTES; Not really possible because of previous check in "parseCredentialSubject"
        return W3CVerificationResult.INVALID_SIGNATURE;

    }

    private W3CVerificationResult verifyOlPsDerivedProofRange(Proof proof, Map<String, Attribute> revealedAttributes, Set<Predicate> rangePredicates, String nonce, long epoch) {
        Object pv=proof.getProofValue();
        if(!(pv instanceof String))
            return W3CVerificationResult.INVALID_TOKEN;
        Map<String, RangePredicateToken> rangeTokens=W3CSerializationUtil.extractRangeTokens(proof);
        if(rangeTokens==null)
            return W3CVerificationResult.INVALID_SIGNATURE;
        if (verificationLibrary.verifyOlPsDerivedProofRange((String) pv, revealedAttributes, rangeTokens, rangePredicates, nonce, epoch) == OLVerificationLibraryResult.VALID) {
            return W3CVerificationResult.VALID;
        } //case INVALID_ATTRIBUTES: return W3CVerificationResult.INVALID_ATTRIBUTES; Not really possible because of previous check in "parseCredentialSubject"
        return W3CVerificationResult.INVALID_SIGNATURE;
    }
}
