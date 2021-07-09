package eu.olympus.client;

import VCModel.VerifiableCredential;
import VCModel.VerifiablePresentation;
import com.google.protobuf.InvalidProtocolBufferException;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.client.interfaces.CredentialStorage;
import eu.olympus.model.*;
import eu.olympus.model.exceptions.MSSetupException;
import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.util.Pair;
import eu.olympus.util.Util;
import eu.olympus.util.W3CSerializationUtil;
import eu.olympus.util.multisign.*;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.psmultisign.*;
import eu.olympus.util.rangeProof.RangePredicateToken;
import eu.olympus.util.rangeProof.RangeProver;
import eu.olympus.util.rangeProof.model.PedersenBase;

import java.net.URI;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

//TODO For exceptions, add at least three types: SetupException, PolicyUnfulfilledException, CredentialGenerationException (for when combination fails)
public class PSCredentialManagement implements CredentialManagement {

    private CredentialStorage credentialStorage;
    private MS multiSignatureScheme;
    private Set<AttributeDefinition> attributeDefinitions;
    private Map<String, AttributeDefinition> attrDefMap;
    private Map<String, AttributeDefinition> attrDefMapShortName;
    private MSpublicParam schemePublicParameters;
    private MSverfKey olympusVerificationKey;
    private PairingBuilder builder;
    private Map<Integer, MSverfKey> verfKeysIdPs;
    private boolean storage;
    private long lifetime;
    int numberOfIdPs;

    public PSCredentialManagement(boolean storage, CredentialStorage credentialStorage, long lifetime) {
        this.storage = storage;
        if (storage && credentialStorage == null)
            throw new IllegalArgumentException("If credentials are going to be stored a Credential Storage must be provided");
        this.credentialStorage = credentialStorage;
        this.lifetime=lifetime;
    }

    public void setup(List<? extends PestoIdP> servers, byte[] seed) {
        numberOfIdPs = servers.size();
        PabcPublicParameters pp = servers.get(0).getPabcPublicParam();
        try {
            schemePublicParameters = new PSpublicParam(pp.getEncodedSchemePublicParam());
        } catch (InvalidProtocolBufferException e) {
            throw new RuntimeException("Could not retrieve scheme public param");
        }
        attributeDefinitions = pp.getAttributeDefinitions();
        if (!checkAttributeDefinitions())
            throw new RuntimeException("Conflicting sets of attribute names");
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
        verfKeysIdPs = new HashMap<>();
        for (int i = 0; i < servers.size(); i++) {
            verificationKeySharesArray[i] = servers.get(i).getPabcPublicKeyShare(); //TODO Concurrent
            verfKeysIdPs.put(i, verificationKeySharesArray[i]);
        }
        this.olympusVerificationKey = multiSignatureScheme.kAggreg(verificationKeySharesArray);
        this.attrDefMap = attributeDefinitions.stream().collect(Collectors.toMap(AttributeDefinition::getId,
                Function.identity()));
        this.attrDefMapShortName=attributeDefinitions.stream().collect(Collectors.toMap(AttributeDefinition::getShortName,
                Function.identity()));
    }

	public void setup(PabcPublicParameters publicParameters, Map<Integer, MSverfKey> verificationKeyShares, byte[] seed) {
    	attributeDefinitions=publicParameters.getAttributeDefinitions();
		try {
			schemePublicParameters = new PSpublicParam(publicParameters.getEncodedSchemePublicParam());
		} catch (InvalidProtocolBufferException e) {
			throw new IllegalArgumentException("Could not retrieve scheme public param");
		}
		if(!checkAttributeDefinitions())
			throw new IllegalArgumentException("Conflicting sets of attribute names");
		multiSignatureScheme = new PSms();
		this.numberOfIdPs = schemePublicParameters.getN();
		PSauxArg auxArg = (PSauxArg) schemePublicParameters.getAuxArg();
		try {
			multiSignatureScheme.setup(numberOfIdPs, auxArg, seed);
		} catch (MSSetupException e) {
			throw new IllegalArgumentException("Wrong public parameters");
		}
		if (verificationKeyShares.keySet().size() != numberOfIdPs)
			throw new IllegalArgumentException("Incorrect number of verification key shares");
		this.verfKeysIdPs = verificationKeyShares;
		try {
			builder = (PairingBuilder) Class.forName(auxArg.getPairingName()).newInstance();
			builder.seedRandom(seed);
		} catch (Exception e) {
			// Should never get here as setup of the scheme requires being able to do this instruction successfully
		}
		MSverfKey[] verificationKeySharesArray = new MSverfKey[verificationKeyShares.keySet().size()];
		int i = 0;
		for (MSverfKey vk : verificationKeyShares.values()) {
			verificationKeySharesArray[i] = vk;
			i++;
		}
		this.olympusVerificationKey = multiSignatureScheme.kAggreg(verificationKeySharesArray);
        this.attrDefMap=attributeDefinitions.stream().collect(Collectors.toMap(AttributeDefinition::getId,
                Function.identity()));
        this.attrDefMapShortName=attributeDefinitions.stream().collect(Collectors.toMap(AttributeDefinition::getShortName,
                Function.identity()));
    }

    public void setupForOffline(PabcPublicParameters publicParameters, MSverfKey olympusVerificationKey, byte[] seed) {
        attributeDefinitions = publicParameters.getAttributeDefinitions();
        try {
            schemePublicParameters = new PSpublicParam(publicParameters.getEncodedSchemePublicParam());
        } catch (InvalidProtocolBufferException e) {
            throw new IllegalArgumentException("Could not retrieve scheme public param");
        }
        if (!checkAttributeDefinitions())
            throw new IllegalArgumentException("Conflicting sets of attribute names");
        multiSignatureScheme = new PSms();
        this.numberOfIdPs = schemePublicParameters.getN();
        PSauxArg auxArg = (PSauxArg) schemePublicParameters.getAuxArg();
        try {
            multiSignatureScheme.setup(numberOfIdPs, auxArg, seed);
        } catch (MSSetupException e) {
            throw new IllegalArgumentException("Wrong public parameters");
        }
        try {
            builder = (PairingBuilder) Class.forName(auxArg.getPairingName()).newInstance();
            builder.seedRandom(seed);
        } catch (Exception e) {
            throw new RuntimeException(e); // Should never get here as setup of the scheme requires being able to do this instruction successfully
        }
        this.olympusVerificationKey = olympusVerificationKey;
        this.attrDefMap = attributeDefinitions.stream().collect(Collectors.toMap(AttributeDefinition::getId,
                Function.identity()));
        this.attrDefMapShortName=attributeDefinitions.stream().collect(Collectors.toMap(AttributeDefinition::getShortName,
                Function.identity()));
    }

    private boolean checkAttributeDefinitions() {
        Set<String> attrIds = attributeDefinitions.stream().map(AttributeDefinition::getId).collect(Collectors.toSet());
        return attrIds.equals(((PSauxArg) schemePublicParameters.getAuxArg()).getAttributes());
    }

    public Pair<PabcPublicParameters, Map<Integer, MSverfKey>> getPublicParams() {
        if (schemePublicParameters == null || verfKeysIdPs == null)
            throw new IllegalStateException("No setup was performed");
        return new Pair<>(new PabcPublicParameters(attributeDefinitions, schemePublicParameters.getEncoded()), verfKeysIdPs);
    }

    public Pair<PabcPublicParameters, MSverfKey> getPublicParamsForOffline() {
        if (schemePublicParameters == null || olympusVerificationKey == null)
            throw new IllegalStateException("No setup was performed");
        return new Pair<>(new PabcPublicParameters(attributeDefinitions, schemePublicParameters.getEncoded()), olympusVerificationKey);
    }

    @Override
    public VerifiablePresentation generatePresentationToken(Policy policy) {
        if (multiSignatureScheme == null) {
            throw new IllegalStateException("It is necessary to run setup (or offlineSetup) before using this method");
        }
        if (credentialStorage == null || !credentialStorage.checkCredential()) {
            throw new IllegalStateException("No credential available to derive the presentation token");
        }
        return tokenFromPolicyAndCredential(policy, credentialStorage.getVCredential());
    }

    @Override
    public VerifiablePresentation combineAndGeneratePresentationToken(Map<Integer, VerifiableCredential> credentialShares,
                                                                      Policy policy) {
        if (verfKeysIdPs == null)
            throw new IllegalStateException("It is necessary to run setup before using this method");
        if (numberOfIdPs != credentialShares.keySet().size())
            throw new IllegalArgumentException("Incorrect number of credentialShares");
        MSverfKey[] verificationKeys = new MSverfKey[numberOfIdPs];
        MSsignature[] psCredentialShares = new MSsignature[numberOfIdPs];
        int i = 0;
        for (Integer id : verfKeysIdPs.keySet()) {
            verificationKeys[i] = verfKeysIdPs.get(id); // instead of i use id
            VerifiableCredential aux = credentialShares.get(id);
            if (aux == null) {
                throw new IllegalArgumentException("No credential share from required IdP");
            }
            try {
                psCredentialShares[i] = new PSsignature(
                        PabcSerializer.PSsignature.parseFrom(
                                Base64.getDecoder().decode(
                                        aux.obtainVCProof().getProofValue().toString())));
            } catch (InvalidProtocolBufferException e) {
                return null;
            } finally {
                i++;
            }
        }
        VerifiableCredential anyCredential = credentialShares.values().iterator().next();
        long epoch = anyCredential.getExpirationDate().getTime();
        Map<String, Object> attributesAux = anyCredential.obtainCredentialSubject();
        Map<String, Attribute> attributes = new HashMap<>();
        for (String name : attributesAux.keySet()) {
            AttributeDefinition def=attrDefMapShortName.get(name);
            if(def==null)
                return null;
            Attribute parsed=parseAttribute(attributesAux.get(name),def);
            if(parsed==null)
                return null;
            attributes.put(def.getShortName(),parsed);
        }
        MSsignature aggSign = null;
        try {
            aggSign = multiSignatureScheme.comb(verificationKeys, psCredentialShares);
            Map<String, ZpElement> attributeZpValues = new HashMap<>();
            for (AttributeDefinition attrDef : attributeDefinitions) {
                Attribute val = attributes.get(attrDef.getShortName());
                ZpElement valTransform = val == null ? builder.getZpElementZero() : builder.getZpElementFromAttribute(val, attrDef);
                attributeZpValues.put(attrDef.getId(), valTransform);
            }
            if (!multiSignatureScheme.verf(olympusVerificationKey, new PSmessage(attributeZpValues, builder.getZpElementFromEpoch(epoch)), aggSign)) {
                return null;
            }
        } catch (Exception e) {
            return null;
        }
        VerifiableCredential temporalCredential = W3CSerializationUtil.generateVCredential(new Date(epoch),
                attributes,
                null, false, "did:olympus:vIdP", null, "AssertionMethod", null, anyCredential.getIssuanceDate(), aggSign.getEnconded(),
                "https://olympus-deployment.eu/example/context", "https://olympus-project.eu/example/validationSchema", "https://olympus-project.eu/example/encodingSchema", URI.create("did:meta:OL-vIdP"));
        if (storage) {
            credentialStorage.storeCredential(temporalCredential);
        }
        return tokenFromPolicyAndCredential(policy, temporalCredential);
    }


    private VerifiablePresentation tokenFromPolicyAndCredential(Policy policy, VerifiableCredential temporalCredential) {
        Map<String, Object> credentialSubject=temporalCredential.obtainCredentialSubject();
        Map<String, ZpElement> attributeZpValues = new HashMap<>();
        Map<String, Attribute> attributesInCred = new HashMap<>();
        for (AttributeDefinition attrDef : attributeDefinitions) {
            Attribute val = parseAttribute(credentialSubject.get(attrDef.getShortName()),attrDef);
            ZpElement valTransform = val == null ? builder.getZpElementZero() : builder.getZpElementFromAttribute(val, attrDef);
            attributeZpValues.put(attrDef.getId(), valTransform);
            if(val!=null)
                attributesInCred.put(attrDef.getShortName(), val);
        }
        Set<String> attributesToRevealId = new HashSet<>();
        Set<String> attributesToRevealShortName = new HashSet<>();
        Set<String> attributesForRangeShortName = new HashSet<>();
        List<Predicate> rangePredicates = new LinkedList<>();
        for (Predicate p : policy.getPredicates()) {
            if (p.getOperation() == Operation.REVEAL) {
                //TODO It should be possible to support "equals" operation (crypto would be the same as reveal, but verifier would use the "requested value" when verifying instead of a value "revealed" by the user within the presentation
                attributesToRevealId.add(p.getAttributeName());
                attributesToRevealShortName.add(attrDefMap.get(p.getAttributeName()).getShortName());
            } else if (p.getOperation() == Operation.INRANGE || p.getOperation() == Operation.GREATERTHAN || p.getOperation() == Operation.LESSTHAN) {
                rangePredicates.add(p);
                attributesForRangeShortName.add(attrDefMap.get(p.getAttributeName()).getShortName());
            } else {
                throw new IllegalArgumentException("Could not satisfy policy: " + p.getOperation() + " is not supported for dp-ABC");
            }
        }

        if (!attributesInCred.keySet().containsAll(attributesToRevealShortName))
            throw new IllegalArgumentException("Could not satisfy policy: credential does not contain every requested attribute");
        if (!attributesInCred.keySet().containsAll(attributesForRangeShortName))
            throw new IllegalArgumentException("Could not satisfy policy: credential does not contain every requested attribute for range predicate");
        if (attributesForRangeShortName.size() != rangePredicates.size())
            throw new IllegalArgumentException("Repeated attribute ID in different range predicates");
        Map<String, Attribute> revealedAttributes = attributesInCred.entrySet().stream()
                .filter(e -> attributesToRevealShortName.contains(e.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        MSmessage signedAttributes = new PSmessage(attributeZpValues,
                builder.getZpElementFromEpoch(temporalCredential.getExpirationDate().getTime()));
        PSsignature ps = null;
        try {
            ps = new PSsignature(PabcSerializer.PSsignature.parseFrom(
                    Base64.getDecoder().decode(
                            temporalCredential.obtainVCProof().getProofValue().toString())));
        } catch (InvalidProtocolBufferException e) {
            return null;
        }
        if (rangePredicates.isEmpty()) {
            MSzkToken token = multiSignatureScheme.presentZKtoken(olympusVerificationKey, attributesToRevealId,
                    signedAttributes, policy.getPolicyId(), ps);
            return W3CSerializationUtil.generatePresentation(
                    W3CSerializationUtil.generateVCredential(
                            temporalCredential.getExpirationDate(),
                            revealedAttributes,
                            null, true, "did:olympus:vIdP", policy.getPolicyId(), "AssertionMethod",
                            null, temporalCredential.getIssuanceDate(), token.getEnconded(),
                            "https://olympus-deployment.eu/example/context", "https://olympus-project.eu/example/validationSchema", "https://olympus-project.eu/example/encodingSchema", URI.create("did:meta:OL-vIdP")),
                    new Date(System.currentTimeMillis()+lifetime*1000),
                    "https://olympus-deployment.eu/example/context");
        } else {
            Map<String, RangePredicateToken> rangePredicateTokenMap = new HashMap<>();
            RangeProver prover = new RangeProver(policy.getPolicyId(), builder);
            PSverfKey key = (PSverfKey) olympusVerificationKey;
            Map<String,Predicate> subjectPredicates=new HashMap<>();
            for (Predicate p : rangePredicates) {
//We know definitions/keys are present because we checked that the attribute is in the credential (only those that are "defined" would be included in a cred)
                String attrId = p.getAttributeName();
                AttributeDefinition definition = attrDefMap.get(attrId);
                String attrShortName=definition.getShortName();
                PedersenBase base = new PedersenBase(key.getVY().get(attrId), key.getVX()); //Base has to be g=Y_j h=X
                rangePredicateTokenMap.put(attrId,
                        prover.generateRangePredicateToken(base,
                                attributesInCred.get(attrShortName),
                                definition,
                                p));
                subjectPredicates.put(attrShortName,p);
            }
            MSzkToken token = multiSignatureScheme.presentZKtokenModified(olympusVerificationKey, attributesToRevealId,
                    prover.getGeneratedCommitments(), signedAttributes, policy.getPolicyId(), ps);
            return W3CSerializationUtil.generatePresentation(
                    W3CSerializationUtil.generateVCredential(
                            temporalCredential.getExpirationDate(),
                            revealedAttributes,
                            subjectPredicates, true, "did:olympus:vIdP", policy.getPolicyId(), "AssertionMethod",
                            getProofRanges(rangePredicates, rangePredicateTokenMap), temporalCredential.getIssuanceDate(), token.getEnconded(),
                            "https://olympus-deployment.eu/example/context", "https://olympus-project.eu/example/validationSchema", "https://olympus-project.eu/example/encodingSchema", URI.create("did:meta:OL-vIdP")),
                    new Date(System.currentTimeMillis()+lifetime*1000),
                    "https://olympus-deployment.eu/example/context");
        }
    }

    @Override
    public void clearCredential() {
        credentialStorage.deleteCredential();
    }

    @Override
    public boolean checkStoredCredential() {
        if (!storage) {
            return false;
        }
        return credentialStorage.checkCredential();
    }

    private Attribute parseAttribute(Object attr, AttributeDefinition definition) {
        if(attr instanceof Integer){
            Attribute attrValue=new Attribute((Integer) attr);
            if (!definition.checkValidValue(attrValue))
                return null;
            return attrValue;
        } else if (attr instanceof Boolean){
            Attribute attrValue=new Attribute((Boolean) attr);
            if (!definition.checkValidValue(attrValue))
                return null;
            return attrValue;
        } else if (attr instanceof String){
            Date parsed= Util.fromRFC3339UTC((String)attr);
            Attribute attrValue= parsed==null? new Attribute((String) attr) : new Attribute(parsed);
            if (!definition.checkValidValue(attrValue))
                return null;
            return attrValue;
        }else
            return null;
    }


    private List<LinkedHashMap<String, Object>> getProofRanges(List<Predicate> rangePredicates, Map<String, RangePredicateToken> rangePredicateTokenMap) {
        List<LinkedHashMap<String, Object>> ranges = new LinkedList<>();
        LinkedHashMap<String, Object> range;
        for(Predicate p: rangePredicates) {
            range = new LinkedHashMap<>();
            range.put("attr", p.getAttributeName());
            range.put("commitment", rangePredicateTokenMap.get(p.getAttributeName()).getEncodedCommitV());
            range.put("lowerBoundProofValue", rangePredicateTokenMap.get(p.getAttributeName()).getProofLowerBound().getEncoded());
            range.put("upperBoundProofValue", rangePredicateTokenMap.get(p.getAttributeName()).getProofUpperBound().getEncoded());
            ranges.add(range);
        }
        return ranges;
    }
}
