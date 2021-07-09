package eu.olympus.util;

import VCModel.*;
import com.google.protobuf.InvalidProtocolBufferException;
import eu.olympus.model.Attribute;
import eu.olympus.model.Operation;
import eu.olympus.model.Predicate;
import eu.olympus.util.rangeProof.RangePredicateToken;

import javax.validation.constraints.NotNull;
import java.net.URI;
import java.util.*;

public class W3CSerializationUtil {

    public static final String GE_TAG="ge";
    public static final String LE_TAG="le";
    public static final String INRANGE_TAG="inRange";
    public static final String OPERATION_TAG="operation";
    public static final String VALUE_TAG="value";
    public static final String LOWER_TAG="lowerBound";
    public static final String UPPER_TAG="upperBound";

    //TODO I think we could include the logic in "getProofRanges" method here instead of the CredentialManagement class
    /**
     * Method for generating a verifiable credential (both for standalone credentials and credentials that will be included in a presentation).
     * @param expiration Expiration date of the credential
     * @param subjectAttributes Attributes that will be included in subject. That is, attributes that form the credential or attributes that will be revealed
     *                          in a presentation
     * @param subjectPredicates Predicates that will be included. keySet correspond to the shortnames of the ids included in the predicates. If the credential is not intended for presentation, this value will be ignored.
     * @param token Indicates whether the VC will be considered as a standalone or for inclusion in a presentation
     * @param verificationMethod VerificationMethod field in proof
     * @param nonce Nonce field in proof
     * @param proofPurpose ProofPurpose field in proof
     * @param rangeProofs RangeProofs field in proof
     * @param issuanceDate Issuance date of the credential
     * @param proofValue ProofValue field in proof
     * @param deploymentContextUrl URL corresponding to the context specific to the deployment
     * @param validationSchemaUrl URL corresponding to the validation schema specific to the deployment
     * @param encodingSchemaUrl URL corresponding to the encoding schema specific to the deployment
     * @param issuerURI URI of the issuer of the credential
     * @return
     */
    public static VerifiableCredential generateVCredential(Date expiration,
                                                           Map<String, Attribute> subjectAttributes,
                                                           Map<String, Predicate> subjectPredicates,
                                                           boolean token,
                                                           Object verificationMethod,
                                                           Object nonce,
                                                           Object proofPurpose,
                                                           Object rangeProofs,
                                                           Date issuanceDate,
                                                           @NotNull String proofValue,
                                                           String deploymentContextUrl,
                                                           String validationSchemaUrl,
                                                           String encodingSchemaUrl,
                                                           URI issuerURI) {
        VerifiableCredential vc = new VerifiableCredential();
        List<String> contexts = new LinkedList<>();
        contexts.add("https://olympus-project.eu/context");
        contexts.add(deploymentContextUrl);
        vc.addContexts(contexts);
        List<CredentialSchema> schemas=new LinkedList<>();
        schemas.add(new CredentialSchema("OlZkValidationSchema", validationSchemaUrl));
        schemas.add(new CredentialSchema("OlZkEncodingSchema", encodingSchemaUrl));
        vc.setCredentialSchema(schemas);
        //vc.setId(URI.create("https://olympus-project.eu/"));                // Set id of verifiable credential
        vc.setIssuer(issuerURI);
        vc.addTypes(Collections.singletonList("OlympusCredential"));        // Credential type name
        vc.setIssuanceDate(issuanceDate);                                     // issued date
        vc.setExpirationDate(expiration);
        if (!token) {
            vc.setCredentialSubject(generateCredentialSubect(subjectAttributes,null));
            vc.setProof(new Proof("OlPsSignature", proofValue, verificationMethod, nonce, expiration.getTime(), proofPurpose, rangeProofs));
        } else {
            vc.setCredentialSubject(generateCredentialSubect(subjectAttributes,subjectPredicates));
            String type = rangeProofs == null ? "OlPsDerivedProof" : "OlPsDerivedProofRange";
            vc.setProof(new Proof(type, proofValue, verificationMethod, nonce, expiration.getTime(), proofPurpose, rangeProofs));
        }
        return vc;
    }


    public static VerifiablePresentation generatePresentation(VerifiableCredential vc, Date expirationDate, String deploymentContextUrl) {
        VerifiablePresentation vp = new VerifiablePresentation();
        List<String> contexts = new LinkedList<>();
        contexts.add("https://olympus-project.org/context");
        contexts.add(deploymentContextUrl);
        vp.setExpirationDate(expirationDate);
        vp.addContexts(contexts);
        //vp.setId(URI.create("https://olympus-project.eu/"));                // Set id of verifiable
        vp.addTypes(Collections.singletonList("OlympusPresentation"));         // Add type name
        vp.addVerifiableCredential(vc);
        return vp;
    }

    public static Map<String, RangePredicateToken> extractRangeTokens(Proof proof) {
        Map<String, RangePredicateToken> result=new HashMap<>();
        try {
            Object aux=proof.getRangeProofs();
            if(aux==null)
                return null;
            List<LinkedHashMap<String, Object>> ranges=(List<LinkedHashMap<String, Object>>)aux;
            for(LinkedHashMap<String, Object> rp:ranges){
                RangePredicateToken tok=new RangePredicateToken((String) rp.get("lowerBoundProofValue"),
                        (String) rp.get("upperBoundProofValue"), (String) rp.get("commitment"));
                result.put((String) rp.get("attr"),tok);
            }
            return result;
        }catch (ClassCastException | InvalidProtocolBufferException e){
            return null;
        }
    }

    private static Map<String,Object> generateCredentialSubect(Map<String, Attribute> attributes, Map<String,Predicate> predicates) {
        Map<String,Object> result=new HashMap<>();
        for(String name:attributes.keySet()){
            result.put(name,attributes.get(name).getAttr());
        }
        if (predicates!=null){
            for(String name:predicates.keySet()){
                result.put(name,serializePredicate(predicates.get(name)));
            }
        }
        return result;
    }

    public static Map<String,Object> serializePredicate(Predicate p) {
        Map<String,Object> predSerial=new HashMap<>();
        predSerial.put(OPERATION_TAG,serializeOperation(p.getOperation()));
        Map<String,Object> values=new HashMap<>();
        switch (p.getOperation()){
            case GREATERTHAN:
                Attribute attr=p.getValue();
                if(attr==null)
                    throw new IllegalArgumentException("Invalid predicate GE");
                values.put(LOWER_TAG,attr.getAttr());
                break;
            case LESSTHAN:
                attr=p.getValue();
                if(attr==null)
                    throw new IllegalArgumentException("Invalid predicate LE");
                values.put(UPPER_TAG,attr.getAttr());
                break;
            case INRANGE:
                attr=p.getValue();
                if(attr==null)
                    throw new IllegalArgumentException("Invalid predicate INRANGE");
                values.put(LOWER_TAG,attr.getAttr());
                attr=p.getExtraValue();
                if(attr==null)
                    throw new IllegalArgumentException("Invalid predicate INRANGE");
                values.put(UPPER_TAG,attr.getAttr());
                break;
            default:
                throw new IllegalArgumentException("Not valid operation for predicate");
        }
        predSerial.put(VALUE_TAG,values);
        return predSerial;
    }

    public static String serializeOperation(Operation operation) {
        switch (operation){
            case GREATERTHAN:
                return GE_TAG;
            case LESSTHAN:
                return LE_TAG;
            case INRANGE:
                return INRANGE_TAG;
            default:
                throw new IllegalArgumentException("Not valid operation for predicate");
        }
    }

    public static Operation parseOperation(Object operation) {
        if(!(operation instanceof String))
            return null;
        switch ((String) operation){
            case GE_TAG:
                return Operation.GREATERTHAN;
            case LE_TAG:
                return Operation.LESSTHAN;
            case INRANGE_TAG:
                return Operation.INRANGE;
            default:
                return null;
        }
    }
}
