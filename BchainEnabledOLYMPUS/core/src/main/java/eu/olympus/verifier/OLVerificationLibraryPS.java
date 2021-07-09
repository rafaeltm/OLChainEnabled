package eu.olympus.verifier;

import VCModel.Verifiable;
import VCModel.VerifiablePresentation;
import com.google.protobuf.InvalidProtocolBufferException;
import eu.olympus.model.*;
import eu.olympus.model.exceptions.MSSetupException;
import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.Pair;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.util.Util;
import eu.olympus.util.W3CSerializationUtil;
import eu.olympus.util.multisign.*;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.psmultisign.*;
import eu.olympus.util.rangeProof.RangePredicateToken;
import eu.olympus.util.rangeProof.RangePredicateVerificationResult;
import eu.olympus.util.rangeProof.RangeVerifier;
import eu.olympus.util.rangeProof.model.PedersenBase;
import eu.olympus.verifier.interfaces.OLVerificationLibrary;
import org.apache.commons.codec.binary.Base64;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import static eu.olympus.util.W3CSerializationUtil.*;

//TODO Revise how exceptions/error flows are handled
public class OLVerificationLibraryPS implements OLVerificationLibrary {

    private MS multiSignatureScheme;
    private Set<AttributeDefinition> attributeDefinitions;
    private Map<String,AttributeDefinition> attrDefMap;
    private Map<String,AttributeDefinition> attrDefMapShortName;
    private MSpublicParam schemePublicParameters;
    private MSverfKey olympusVerificationKey;
    private PairingBuilder builder;

    public void setup(List<? extends PestoIdP> servers, byte[] seed){
        PabcPublicParameters publicParameters = servers.get(0).getPabcPublicParam();
        try {
            schemePublicParameters = new PSpublicParam(publicParameters.getEncodedSchemePublicParam());
        } catch (InvalidProtocolBufferException e) {
            throw new RuntimeException("Could not retrieve scheme public param");
        }
        attributeDefinitions=publicParameters.getAttributeDefinitions();
        if(!checkAttributeDefinitions())
            throw new IllegalArgumentException("Conflicting sets of attribute names");
        multiSignatureScheme = new PSms();
        PSauxArg auxArg = (PSauxArg) schemePublicParameters.getAuxArg();
        try {
            multiSignatureScheme.setup(schemePublicParameters.getN(), auxArg, seed);
            builder = (PairingBuilder) Class.forName(auxArg.getPairingName()).newInstance();
            builder.seedRandom(seed);
        } catch (Exception e) {
            throw new RuntimeException("Could not create scheme");
        }
        MSverfKey[] verificationKeySharesArray = new MSverfKey[servers.size()];
        for (int i = 0; i < servers.size(); i++) {
            verificationKeySharesArray[i] = servers.get(i).getPabcPublicKeyShare(); //TODO Concurrent
        }
        this.olympusVerificationKey = multiSignatureScheme.kAggreg(verificationKeySharesArray);
        this.attrDefMap=attributeDefinitions.stream().collect(Collectors.toMap(AttributeDefinition::getId,
                Function.identity()));
        this.attrDefMapShortName=attributeDefinitions.stream().collect(Collectors.toMap(AttributeDefinition::getShortName,
                Function.identity()));
    }

    public void setup(PabcPublicParameters publicParameters, MSverfKey olympusVerificationKey, byte[] seed) throws MSSetupException {
        attributeDefinitions=publicParameters.getAttributeDefinitions();
        try {
            schemePublicParameters = new PSpublicParam(publicParameters.getEncodedSchemePublicParam());
        } catch (InvalidProtocolBufferException e) {
            throw new IllegalArgumentException("Could not retrieve scheme public param");
        }
        multiSignatureScheme=new PSms();
        PSauxArg auxArg= (PSauxArg) schemePublicParameters.getAuxArg();
        multiSignatureScheme.setup(schemePublicParameters.getN(),auxArg, seed);
        if(!checkAttributeDefinitions())
            throw new IllegalArgumentException("Conflicting sets of attribute names");
        this.olympusVerificationKey=olympusVerificationKey;
        try {
            builder=(PairingBuilder) Class.forName(auxArg.getPairingName()).newInstance();
            builder.seedRandom(seed);
        } catch (Exception e) {
            throw new RuntimeException(e);
            //Should never reach this point, as the newInstance method must be successful for setting up the scheme
        }
        this.attrDefMap=attributeDefinitions.stream().collect(Collectors.toMap(AttributeDefinition::getId,
                Function.identity()));
        this.attrDefMapShortName=attributeDefinitions.stream().collect(Collectors.toMap(AttributeDefinition::getShortName,
                Function.identity()));
    }

    public Pair<PabcPublicParameters,MSverfKey> getPublicParams(){
        if(multiSignatureScheme==null)
            throw new IllegalStateException("No setup was performed");
        return new Pair<>(new PabcPublicParameters(attributeDefinitions,schemePublicParameters.getEncoded()),olympusVerificationKey);
    }


    @Override
    public OLVerificationLibraryResult verifyOlPsDerivedProof(String token, Map<String, Attribute> revealedAttributes, String nonce, long epoch) {
        if(multiSignatureScheme==null) {
            throw new IllegalStateException("It is necessary to run setup before using this method");
        }
        MSzkToken reconstructedToken;
        try {
            reconstructedToken=new PSzkToken(PabcSerializer.PSzkToken.parseFrom(Base64.decodeBase64(token)));
        } catch (InvalidProtocolBufferException e) {
            return OLVerificationLibraryResult.INVALID_SIGNATURE;
        }
        if(!attrDefMap.keySet().containsAll(revealedAttributes.keySet()))
            return OLVerificationLibraryResult.INVALID_ATTRIBUTES;
        Map<String, ZpElement> revealedZpAttributes=transformAttributes(revealedAttributes);
        MSmessage revealedAttributesMessage=new PSmessage(revealedZpAttributes,builder.getZpElementFromEpoch(epoch));
        if(!multiSignatureScheme.verifyZKtoken(reconstructedToken,olympusVerificationKey,nonce,revealedAttributesMessage))
            return OLVerificationLibraryResult.INVALID_SIGNATURE;
        return OLVerificationLibraryResult.VALID;
    }

    @Override
    public OLVerificationLibraryResult verifyOlPsDerivedProofRange(String token, Map<String, Attribute> revealedAttributes, Map<String, RangePredicateToken> rangeTokens, Set<Predicate> rangePredicates, String nonce, long epoch) {
        if(multiSignatureScheme==null) {
            throw new IllegalStateException("It is necessary to run setup before using this method");
        }
        MSzkToken reconstructedToken;
        try {
            reconstructedToken=new PSzkTokenModified(PabcSerializer.PSzkTokenModified.parseFrom(Base64.decodeBase64(token)));
        } catch (InvalidProtocolBufferException e) {
            return OLVerificationLibraryResult.INVALID_SIGNATURE;
        }
        if(!attrDefMap.keySet().containsAll(revealedAttributes.keySet()) || !attrDefMap.keySet().containsAll(rangeTokens.keySet()))
            return OLVerificationLibraryResult.INVALID_ATTRIBUTES;
        if(!rangeTokens.keySet().equals(rangePredicates.stream().map(Predicate::getAttributeName).collect(Collectors.toSet())))
            return OLVerificationLibraryResult.INVALID_SIGNATURE;
        Map<String, Group1Element> Vp=rangeTokens.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().getCommitV()));
        Map<String, ZpElement> revealedZpAttributes=transformAttributes(revealedAttributes);
        MSmessage revealedAttributesMessage=new PSmessage(revealedZpAttributes,builder.getZpElementFromEpoch(epoch));
        if(!multiSignatureScheme.verifyZKtokenModified(reconstructedToken,olympusVerificationKey,nonce, revealedAttributesMessage,Vp))
            return OLVerificationLibraryResult.INVALID_SIGNATURE;
        RangeVerifier verifier=new RangeVerifier(nonce,builder);
        PSverfKey key = (PSverfKey) olympusVerificationKey;
        for(Predicate p:rangePredicates){
            String attrId=p.getAttributeName();
            AttributeDefinition def=attrDefMap.get(attrId);//Already checked that they are all present
            PedersenBase base = new PedersenBase(key.getVY().get(attrId), key.getVX()); //Base has to be g=Y_j h=X
            if(verifier.verifyRangePredicate(base,rangeTokens.get(attrId),def,p)== RangePredicateVerificationResult.INVALID)
                return OLVerificationLibraryResult.INVALID_SIGNATURE;
        }
        return OLVerificationLibraryResult.VALID;
    }

    public Pair<Map<String, Attribute>, Set<Predicate>> parseCredentialSubject(Map<String, Object> subject) {
        Map<String, Attribute> revealedAttributes=new HashMap<>();
        Set<Predicate> predicates=new HashSet<>();
        for(String name:subject.keySet()){
            AttributeDefinition definition=attrDefMapShortName.get(name);
            if(definition==null)
                return null;
            String id=definition.getId();
            Object serialValue=subject.get(name);
            if(serialValue instanceof Integer){
                Attribute attrValue=new Attribute((Integer) serialValue);
                if (!definition.checkValidValue(attrValue))
                    return null;
                revealedAttributes.put(id,attrValue);
            } else if (serialValue instanceof Boolean){
                Attribute attrValue=new Attribute((Boolean) serialValue);
                if (!definition.checkValidValue(attrValue))
                    return null;
                revealedAttributes.put(id,attrValue);
            } else if (serialValue instanceof String){
                Date parsed= Util.fromRFC3339UTC((String)serialValue);
                Attribute attrValue= parsed==null? new Attribute((String) serialValue) : new Attribute(parsed);
                if (!definition.checkValidValue(attrValue))
                    return null;
                revealedAttributes.put(id,attrValue);
            } else if (serialValue instanceof Map<?, ?>) {
                Predicate parsed=parsePredicate(id, (Map<?, ?>) serialValue);
                if(parsed==null)
                    return null;
                predicates.add(parsed);
            }
        }
        return new Pair<>(revealedAttributes,predicates);
    }

    private Predicate parsePredicate(String id, Map<?, ?> serialValue) {
        try {
            Operation op=W3CSerializationUtil.parseOperation(serialValue.get(OPERATION_TAG));
            if(op==null)
                return null;
            Map<?,?> values= (Map<?, ?>) serialValue.get(VALUE_TAG);
            if(values==null)
                return null;
            Attribute lowerBound=attrFromObject(values.get(LOWER_TAG));
            Attribute upperBound=attrFromObject(values.get(UPPER_TAG));
            if(lowerBound!=null)
                return new Predicate(id,op,lowerBound,upperBound);
            else
                return new Predicate(id,op,upperBound,null);
        } catch (Exception e){
            return null;
        }
    }

    private Attribute attrFromObject(Object attr) {
        if (attr instanceof Integer)
            return new Attribute((Integer) attr);
        if (attr instanceof String){
            Date parsed=Util.fromRFC3339UTC((String) attr);
            if(parsed==null)
                return null;
            return new Attribute(parsed);
        }
        return null;
    }


    //This may have to become a public method executed by the W3C verifier. Another option (maybe the best) would be having the extraction return already transformed elements
    // and work with that in the verifier
    private Map<String, ZpElement> transformAttributes(Map<String, Attribute> revealedAttributes) {
        Map<String, ZpElement> result=new HashMap<>();
        for(String attr:revealedAttributes.keySet()){
            Attribute attrValue=revealedAttributes.get(attr);
            AttributeDefinition def=attrDefMap.get(attr); // Already checked that they are all present
            result.put(attr,builder.getZpElementFromAttribute(attrValue,def));
        }
        return result;
    }

    private boolean checkAttributeDefinitions() {
        Set<String> attrIds=attributeDefinitions.stream().map(e->e.getId()).collect(Collectors.toSet());
        return attrIds.equals(((PSauxArg) schemePublicParameters.getAuxArg()).getAttributes());
    }

}
