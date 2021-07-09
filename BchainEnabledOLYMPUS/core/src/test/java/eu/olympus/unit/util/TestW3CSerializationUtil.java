package eu.olympus.unit.util;

import VCModel.Verifiable;
import VCModel.VerifiableCredential;
import VCModel.VerifiablePresentation;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.model.*;
import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.Util;
import eu.olympus.util.W3CSerializationUtil;
import eu.olympus.util.rangeProof.RangePredicateToken;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

public class TestW3CSerializationUtil {

	private static final String EXAMPLE_CRED="{\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.eu/context\",\"https://olympus-deployment.eu/example/context\"],\"type\":[\"VerifiableCredential\",\"OlympusCredential\"],\"credentialSchema\":[{\"id\":\"https://olympus-project.eu/example/validationSchema\",\"type\":\"OlZkValidationSchema\"},{\"id\":\"https://olympus-project.eu/example/encodingSchema\",\"type\":\"OlZkEncodingSchema\"}],\"issuer\":\"did:meta:OL-vIdP\",\"issuanceDate\":\"2021-03-17T11:02:35\",\"expirationDate\":\"2021-06-04T00:00:00\",\"credentialSubject\":{\"hasDL\":true,\"name\":\"John\",\"dateOfBirth\":\"1993-06-04T00:00:00\",\"height\":180},\"proof\":{\"type\":\"OlPsSignature\",\"epoch\":1622764800000,\"proofValue\":\"proofValueExample\",\"proofPurpose\":\"AssertionMethod\",\"verificationMethod\":\"verificationMethodExample\"}}";
	private static final String EXAMPLE_PRES="{\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.org/context\",\"https://olympus-deployment.eu/example/context\"],\"type\":[\"VerifiablePresentation\",\"OlympusPresentation\"],\"expirationDate\":\"2021-06-04T00:00:00\",\"verifiableCredential\":[{\"expirationDate\":\"2021-06-04T00:00:00\",\"issuer\":\"did:meta:OL-vIdP\",\"issuanceDate\":\"2021-03-17T11:02:35\",\"credentialSubject\":{\"hasDL\":true,\"name\":\"John\"},\"credentialSchema\":[{\"id\":\"https://olympus-project.eu/example/validationSchema\",\"type\":\"OlZkValidationSchema\"},{\"id\":\"https://olympus-project.eu/example/encodingSchema\",\"type\":\"OlZkEncodingSchema\"}],\"type\":[\"VerifiableCredential\",\"OlympusCredential\"],\"proof\":{\"type\":\"OlPsDerivedProof\",\"proofValue\":\"proofValueExample\",\"nonce\":\"nonceExample1\",\"verificationMethod\":\"verificationMethodExample\",\"proofPurpose\":\"AssertionMethod\",\"epoch\":1622764800000},\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.eu/context\",\"https://olympus-deployment.eu/example/context\"]}]}";
	private static final String EXAMPLE_PRES_RANGE="{\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.org/context\",\"https://olympus-deployment.eu/example/context\"],\"type\":[\"VerifiablePresentation\",\"OlympusPresentation\"],\"expirationDate\":\"2021-06-04T00:00:00\",\"verifiableCredential\":[{\"expirationDate\":\"2021-06-04T00:00:00\",\"issuer\":\"did:meta:OL-vIdP\",\"issuanceDate\":\"2021-03-17T11:02:35\",\"credentialSubject\":{\"hasDL\":true,\"name\":\"John\",\"height\":{\"operation\":\"ge\",\"value\":{\"lowerBound\":180}}},\"credentialSchema\":[{\"id\":\"https://olympus-project.eu/example/validationSchema\",\"type\":\"OlZkValidationSchema\"},{\"id\":\"https://olympus-project.eu/example/encodingSchema\",\"type\":\"OlZkEncodingSchema\"}],\"type\":[\"VerifiableCredential\",\"OlympusCredential\"],\"proof\":{\"type\":\"OlPsDerivedProofRange\",\"proofValue\":\"proofValueExample\",\"rangeProofs\":[{\"attr\":\"height\",\"commitment\":\"commitmentExample\",\"lowerBoundProofValue\":\"lowerProofExample\",\"upperBoundProofValue\":\"upperProofExample\"}],\"verificationMethod\":\"verificationMethodExample\",\"nonce\":\"nonceExample2\",\"epoch\":1622764800000,\"proofPurpose\":\"AssertionMethod\"},\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.eu/context\",\"https://olympus-deployment.eu/example/context\"]}]}";
	private static final String ENCODED_RANGETOKEN1="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";
	private static final String ENCODED_RANGETOKEN2="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";

	@Test
	public void testGenerateVCredential() throws IOException {
		Date expiration=Util.fromRFC3339UTC("2021-06-04T00:00:00");
		Date issuance=Util.fromRFC3339UTC("2021-03-17T11:02:35");
		Map<String,Attribute> attributeMap=new HashMap<>();
		attributeMap.put("name",new Attribute("John"));
		attributeMap.put("height",new Attribute(180));
		attributeMap.put("hasDL",new Attribute(true));
		attributeMap.put("dateOfBirth",new Attribute(Util.fromRFC3339UTC("1993-06-04T00:00:00")));
		VerifiableCredential cred=W3CSerializationUtil.generateVCredential(expiration,attributeMap, null, false, "verificationMethodExample", null, "AssertionMethod", null, issuance, "proofValueExample",
				"https://olympus-deployment.eu/example/context", "https://olympus-project.eu/example/validationSchema", "https://olympus-project.eu/example/encodingSchema", URI.create("did:meta:OL-vIdP"));
		ObjectMapper mapper=new ObjectMapper();
		assertThat(mapper.readTree(cred.toJSONString()).equals(mapper.readTree(EXAMPLE_CRED)),is(true));
	}

	@Test
	public void testGenerateVPresentation() throws IOException {
		Map<String, AttributeDefinition> defForTest=new HashMap<>();
		defForTest.put("uri:Height",new AttributeDefinitionInteger("uri:Height","height",0,260));
		Date expiration=Util.fromRFC3339UTC("2021-06-04T00:00:00");
		Date issuance=Util.fromRFC3339UTC("2021-03-17T11:02:35");
		Map<String,Attribute> attributeMap1=new HashMap<>();
		attributeMap1.put("name",new Attribute("John"));
		attributeMap1.put("hasDL",new Attribute(true));
		VerifiableCredential credWithoutRange=W3CSerializationUtil.generateVCredential(expiration,attributeMap1, null, true, "verificationMethodExample", "nonceExample1", "AssertionMethod", null, issuance, "proofValueExample",
				"https://olympus-deployment.eu/example/context", "https://olympus-project.eu/example/validationSchema", "https://olympus-project.eu/example/encodingSchema", URI.create("did:meta:OL-vIdP"));
		VerifiablePresentation pres=W3CSerializationUtil.generatePresentation(credWithoutRange,  credWithoutRange.getExpirationDate(), "https://olympus-deployment.eu/example/context");
		Map<String,Attribute> attributeMap2=new HashMap<>();
		attributeMap2.put("name",new Attribute("John"));
		attributeMap2.put("hasDL",new Attribute(true));
		// Include map for range predicates
		List<LinkedHashMap<String, Object>> ranges = new LinkedList<>();
		LinkedHashMap<String, Object> range = new LinkedHashMap<>();
		range.put("attr","height");
		range.put("commitment", "commitmentExample");
		range.put("lowerBoundProofValue", "lowerProofExample");
		range.put("upperBoundProofValue", "upperProofExample");
		ranges.add(range);
		Set<Predicate> predicates=new HashSet<>();
		predicates.add(new Predicate("uri:Height", Operation.GREATERTHAN,new Attribute(180)));
		Map<String,Predicate> predicateMap= predicates.stream().collect(Collectors.toMap(p->defForTest.get(p.getAttributeName()).getShortName(), Function.identity()));
		VerifiableCredential credWithRange=W3CSerializationUtil.generateVCredential(expiration,attributeMap2, predicateMap, true, "verificationMethodExample", "nonceExample2", "AssertionMethod", ranges, issuance, "proofValueExample",
				"https://olympus-deployment.eu/example/context", "https://olympus-project.eu/example/validationSchema", "https://olympus-project.eu/example/encodingSchema", URI.create("did:meta:OL-vIdP"));
		VerifiablePresentation presRange=W3CSerializationUtil.generatePresentation(credWithRange, credWithRange.getExpirationDate(), "https://olympus-deployment.eu/example/context");
		ObjectMapper mapper=new ObjectMapper();
		assertThat(mapper.readTree(pres.toJSONString()).equals(mapper.readTree(EXAMPLE_PRES)),is(true));
		assertThat(mapper.readTree(presRange.toJSONString()).equals(mapper.readTree(EXAMPLE_PRES_RANGE)),is(true));
	}


	@Test
	public void testExtractRangeTokens() throws IOException {
		Date expiration=Util.fromRFC3339UTC("2021-06-04T00:00:00");
		Date issuance=Util.fromRFC3339UTC("2021-03-17T11:02:35");
		Map<String,Attribute> attributeMap=new HashMap<>();
		attributeMap.put("name",new Attribute("John"));
		//attributeMap.put("height",new Attribute(180));
		attributeMap.put("hasDL",new Attribute(true));
		List<LinkedHashMap<String, Object>> ranges = new LinkedList<>();
		LinkedHashMap<String, Object> range = new LinkedHashMap<>();
		RangePredicateToken token1=new RangePredicateToken(PabcSerializer.RangePredToken.parseFrom(Base64.decodeBase64(ENCODED_RANGETOKEN1)));
		range.put("attr","height");
		range.put("commitment", token1.getEncodedCommitV());
		range.put("lowerBoundProofValue", token1.getProofLowerBound().getEncoded());
		range.put("upperBoundProofValue", token1.getProofUpperBound().getEncoded());
		ranges.add(range);
		range = new LinkedHashMap<>();
		RangePredicateToken token2=new RangePredicateToken(PabcSerializer.RangePredToken.parseFrom(Base64.decodeBase64(ENCODED_RANGETOKEN2)));
		range.put("attr","age");
		range.put("commitment", token2.getEncodedCommitV());
		range.put("lowerBoundProofValue", token2.getProofLowerBound().getEncoded());
		range.put("upperBoundProofValue", token2.getProofUpperBound().getEncoded());
		ranges.add(range);
		VerifiableCredential cred=W3CSerializationUtil.generateVCredential(expiration,attributeMap, null, true, "verificationMethodExample", null, "AssertionMethod", ranges, issuance, "proofValueExample",
				"https://olympus-deployment.eu/example/context", "https://olympus-project.eu/example/validationSchema", "https://olympus-project.eu/example/encodingSchema", URI.create("did:meta:OL-vIdP"));
		VerifiableCredential reconstructedCred=new VerifiableCredential(Verifiable.getJSONMap(cred.toJSONString()));
		//System.out.println(reconstructedCred.toJSONString());
		Map<String,RangePredicateToken> tokens=W3CSerializationUtil.extractRangeTokens(reconstructedCred.obtainVCProof());
		assertThat(tokens.get("height").getEncoded().equals(ENCODED_RANGETOKEN1),is(true));
		assertThat(tokens.get("age").getEncoded().equals(ENCODED_RANGETOKEN2),is(true));
	}

	@Test
	public void testExtractRangeTokensFails() throws IOException {
		Date expiration=Util.fromRFC3339UTC("2021-06-04T00:00:00");
		Date issuance=Util.fromRFC3339UTC("2021-03-17T11:02:35");
		Map<String,Attribute> attributeMap=new HashMap<>();
		attributeMap.put("name",new Attribute("John"));
		//attributeMap.put("height",new Attribute(180));
		attributeMap.put("hasDL",new Attribute(true));
		List<LinkedHashMap<String, Object>> ranges = new LinkedList<>();
		LinkedHashMap<String, Object> range = new LinkedHashMap<>();
		RangePredicateToken token1=new RangePredicateToken(PabcSerializer.RangePredToken.parseFrom(Base64.decodeBase64(ENCODED_RANGETOKEN1)));
		range.put("attr","height");
		range.put("commitment", token1.getEncodedCommitV());
		range.put("lowerBoundProofValue", token1.getProofLowerBound().getEncoded());
		ranges.add(range);
		VerifiableCredential cred=W3CSerializationUtil.generateVCredential(expiration,attributeMap, null, true, "verificationMethodExample", null, "AssertionMethod", ranges, issuance, "proofValueExample",
				"https://olympus-deployment.eu/example/context", "https://olympus-project.eu/example/validationSchema", "https://olympus-project.eu/example/encodingSchema", URI.create("did:meta:OL-vIdP"));
		VerifiableCredential reconstructedCred=new VerifiableCredential(Verifiable.getJSONMap(cred.toJSONString()));
		ranges = new LinkedList<>();
		range = new LinkedHashMap<>();
		RangePredicateToken token2=new RangePredicateToken(PabcSerializer.RangePredToken.parseFrom(Base64.decodeBase64(ENCODED_RANGETOKEN2)));
		range.put("attr","age");
		range.put("commitment", token2.getEncodedCommitV());
		range.put("lowerBoundProofValue", "wrongSerial");
		range.put("upperBoundProofValue", token2.getProofUpperBound().getEncoded());
		ranges.add(range);
		VerifiableCredential cred2=W3CSerializationUtil.generateVCredential(expiration,attributeMap, null, true, "verificationMethodExample", null, "AssertionMethod", ranges, issuance, "proofValueExample",
				"https://olympus-deployment.eu/example/context", "https://olympus-project.eu/example/validationSchema", "https://olympus-project.eu/example/encodingSchema", URI.create("did:meta:OL-vIdP"));
		VerifiableCredential reconstructedCred2=new VerifiableCredential(Verifiable.getJSONMap(cred2.toJSONString()));
		assertNull(W3CSerializationUtil.extractRangeTokens(reconstructedCred2.obtainVCProof()));
	}

	@Test
	public void testSerializePredicateErrors() throws IOException {
		Predicate wrongOperation=new Predicate("name",Operation.EQ,null);
		Predicate invalidGE=new Predicate("name",Operation.GREATERTHAN,null);
		Predicate invalidLE=new Predicate("name",Operation.GREATERTHAN,null);
		Predicate invalidINRANGE=new Predicate("name",Operation.INRANGE,null,new Attribute(2));
		Predicate invalidINRANGEextraValue=new Predicate("name",Operation.GREATERTHAN,new Attribute(2),null);
		try{
			W3CSerializationUtil.serializePredicate(wrongOperation);
		}catch (IllegalArgumentException e){
		}
		try{
			W3CSerializationUtil.serializePredicate(invalidGE);
		}catch (IllegalArgumentException e){
		}
		try{
			W3CSerializationUtil.serializePredicate(invalidLE);
		}catch (IllegalArgumentException e){
		}
		try{
			W3CSerializationUtil.serializePredicate(invalidINRANGE);
		}catch (IllegalArgumentException e){
		}
		try{
			W3CSerializationUtil.serializePredicate(invalidINRANGEextraValue);
		}catch (IllegalArgumentException e){
		}
	}

	@Test (expected = IllegalArgumentException.class)
	public void testSerializeOperationError() {
		W3CSerializationUtil.serializeOperation(Operation.EQ);
	}

}
