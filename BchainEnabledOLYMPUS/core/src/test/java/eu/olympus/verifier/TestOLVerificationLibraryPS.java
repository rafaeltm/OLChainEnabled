package eu.olympus.verifier;

import VCModel.Verifiable;
import VCModel.VerifiableCredential;
import VCModel.VerifiablePresentation;
import eu.olympus.model.*;

import java.util.*;
import java.util.stream.Collectors;

import eu.olympus.server.ThresholdPSSharesGenerator;
import eu.olympus.server.interfaces.CredentialGenerator;
import eu.olympus.unit.util.multisingMock.MockPublicParam;
import eu.olympus.util.Pair;
import eu.olympus.util.Util;
import eu.olympus.util.multisign.MSauxArg;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.util.psmultisign.PSauxArg;
import eu.olympus.util.psmultisign.PSms;
import eu.olympus.util.rangeProof.RangePredicateToken;
import eu.olympus.util.rangeProof.model.RangeProof;
import eu.olympus.verifier.interfaces.OLVerificationLibrary;
import org.apache.commons.codec.binary.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.google.protobuf.InvalidProtocolBufferException;

import eu.olympus.model.exceptions.MSSetupException;
import eu.olympus.server.PestoIdPImpl;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.storage.InMemoryPestoDatabase;
import eu.olympus.util.multisign.MSpublicParam;
import eu.olympus.util.psmultisign.PSpublicParam;
import eu.olympus.util.psmultisign.PSverfKey;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

public class TestOLVerificationLibraryPS {

	@Rule
	public final ExpectedException exception = ExpectedException.none();
	private static final String key0 = "CnoKeAo6EisbfOFyTuoKozbyRISSwM85o5IXfiYZltcKGwoHoVFoHkBXJvnjn8YDczF/nZ8sdu/8QpHsMZX4IhI6B7/noK3X0V5VAZ7cHLJNypLqZWxSgqwMKDwj7Yk7k9L7j4Dk9S1u5zf2h3t5dQO04KT3111w1baUBRJ6CngKOhLrSyt1mP/V9WdMeO9EOSxLNKSGARwEHyktfSMVtoeDp9vMXNkUPJi70CV82k0rhF/3lFllvfuhFlQSOgk9TB/91EjG93BwdeZBKWDTkV3lhGGGCU2Lon4goo7Jmu4E0yAsy3Cw45/nCXziiu/l5vBiXm9/j68aegp4CjoQfH7QJG1AXoKkLQ0d7jWqFKV3eXpvGa7MiDB2miyW8y/SXxnT/ANYrLboa9YuZMQzUAL1F8MXI9b6EjoJlBYVWdBNKysboy8Ii4+ioiFmfTY4FlRSIZwLIj3V0gqscd0xjSSQKFxoBMtIe6oIGI4+eT/MvGBQIoEBCgNOb3cSegp4CjoABFx2HPX7IrN/u40TelnmU8QcMvCL4iiWmB3Pw2hq3eeBB8L+9ycKu9Xrl0pDCEpeKGNKcb4XCJwfEjoBaQxyimDo/Q/Q8j4fiWz/+DYcTF9aBlCxz8NMg4j9do2La6juzzckAcK22K23wzdxR4/ySjF2IAjOIoEBCgNBZ2USegp4CjoQ1TdDVXwg4HowwLLNwo3dhvs8BpC6EvUHKQQKb3eBwheajbWFrHWcciBqILv/fyWKzSMZ0STBiY+1EjoE//2Jqk0zpzJt10Vg2IZ/EZMhIPeVf21HfWGcTCEHuwYQEChVu4lrwRRZA7BbzXvUP0l9y3YSQjhnIoIBCgROYW1lEnoKeAo6AzuLurQtXjxmt9nHOisR7THToYYnL/Gvqh43HAHdpwv75iO1QtORycj7UL4vIAJop8VuvE+eAWkKoRI6BBMy5BG+qKntrFM5Z4k2pR7ToSp3zH4UYCKDNcZhXpiy0IjqpVG/4dGrciQY6x/gepIjOKl8ROOSrA==";
	private static final String param = "CAMSRAoyZXUub2x5bXB1cy51dGlsLnBhaXJpbmdCTFM0NjEuUGFpcmluZ0J1aWxkZXJCTFM0NjESA05vdxIDQWdlEgROYW1l";
	private static final byte[] seed = "random value random value random value random value random".getBytes();
	private static final String PAIRING_NAME = "eu.olympus.util.pairingBLS461.PairingBuilderBLS461";
	private static final String TEST_RANGE_TOKEN = "CvMBCvABCjoGDm65uCEja5Z2bG/STtlQFgC35hmYwFtCYyFuMPk/SMv9p9vPezf0OIzOJmVnGC/S8A/BliAoHUKbEjoT+KeHd643DjnhNO6gctGJwUObafcdrSBluzbuIPHtT5RpENpT9uwAAFTFg9CZ6Mw0IPOdhVcl3WZSGjoBmg0VLr9m60kWMfxRAQ9RL5A7L23sPEst91+hx09ZeEG11sV3i1S00JnYL9IsVcwkT43Empy5H7tfIjoP0aAvzpMLdQ2xhI40C/ernBpy8Rpgf2U9Bdlhyf/ovOW+01MSTUtevjnRcNmeB53THytqfETY+G+KEvMBCvABCjoPgijIHrad1sUFIDzwLHgi3w9YPhYPMxRupxgljuzyYrdFuOhlG4BehvUHD9U3ZtzPWh6/GtxKxmxWEjoC0qySsPrF/TmbH9+t4XEUKtoh8h0h183of2w9HF1lA/dzI0bKbJeP8bLlvbYJ2/HyIxvKT5mX8VQGGjoUnEEUGHZJT3XMjLlPv1NRGUsbBJ1HdIk735GhdsDtR0CBrKDyeTV1wstROV+0+uqjaxOl85yGZHxnIjoIMNcEoMP1Xh/0lWNjFXCe5OQo1UMzwT4PUoQxd9vEGjwRc04VqXYsLDXihq6gBzBILen1+Q90FUrgGjwKOgAAAAAAAAAAAAAAAAAAAAAAAAACAMwUbIsidmPm37YTlcodM+9OAMY/E4AIZ0gdjFCDqU+AM1ED3eUiRwoHdXJpOkFnZRI8CjoAAAAAAAAAAAAAAAAAAAAAAAAACBuJLg9xR3NzwaWg8LeO41DDTZlesLufxcBVKL9RzYqsx659VOOdIkgKCHVyaTpOYW1lEjwKOgAAAAAAAAAAAAAAAAAAAAAAAAANn/jC7TdPMZ37a9r0di3ZTP7+oFMTz+v/sLd0PslWrcguUdpKbzgqPAo6AAAAAAAAAAAAAAAAAAAAAAAAAAIvmI3IdlZwoI2fOT9mi2ODsDYM5QuUQ36nA7IJesXwh9RHhGDdyTI8CjoAAAAAAAAAAAAAAAAAAAAAAAAADBMqcDuDn1tO4e2wfILoH3ntPUchQDCzLU6YAyZlp1rpZOSMW63VOkcKB3VyaTpBZ2USPAo6AAAAAAAAAAAAAAAAAAAAAAAAAA9E2o/f/XGHWNIqqmGyV0qJT6nNbEIAmO7rAsFVwr/qgP33FHqPMQ==";
	private static final String TEST_TOKEN = "CvMBCvABCjoLdtbTzdD6+bV2Fk1GQ+07+sxGzWImPyiKzbotwL9syhGMrJCctOlZGEkRMjCNJ95FqjnQOga9nrJYEjoBHFdvvJvUfvzT2pS2CatS66woap4YxGtpquCN6q0AmG3fb9stZw+55QPLLfkF31fruG14C5/gfrS3GjoCMwZZyJwCyHZU6zDKjE6wk8J0Iiircjdg4tKt68F0NmblPV9zpmSoNgWXopSuPdupXOZ83MPBH4MHIjoMj4MbaiYWj5JJvjV2oVX2BhG4DTSE3+MaLrmxMNWQ4bl1mV1b6mubtcDtmtngd3m9tbO18X4vN3k/EvMBCvABCjoC/2fuCAkRhSNTd/lXASYLMgx+932J7WtB1MIgslezDuoA0vZSh2LN/kKd1fPVArR6FZAQaysAKrBhEjoJHDdG89XUgbyWdnWesPJynuWQqoW6vUdADirT6I0aN0SGkIpUH6kshfRio+8NjalMJ7s42x7LstGuGjoLONX1y9y8xcf9kQiEvU29OSqHUV4X9osbREaLfNPdw9W8lXXfOmCLNtkeHdICKj8CRiOv34eLSOqVIjoMdXKbG3YUVDK7Lms/nAM6jWWSp//eldyx6eeih9mJJK5Mbz4v7SxHbS9Sdw6HxJ7PGJVnnvQVoz2UGjwKOgAAAAAAAAAAAAAAAAAAAAAAAAABDCb8BboUZqZs5mw7Ctb8WimyLS6AFz1P6u+rXcfdi7H2CkZwua0iSAoIdXJpOk5hbWUSPAo6AAAAAAAAAAAAAAAAAAAAAAAAAAqvmkHWQl/xj2T7z1Yjc9nqpWNa2WFLm+1LPSJ+85r3/1l3j/EI3So8CjoAAAAAAAAAAAAAAAAAAAAAAAAACGZsM9ssFJvwJE/ui+ol1Y3uro/3G4Hn3wInQVWM1E062UUW+9BbMjwKOgAAAAAAAAAAAAAAAAAAAAAAAAAJd+jXlAfKxcJSmuZQNh8sNq2BuJgMb/SSLeoxTeGdcX1Cjluow6g=";



	@Test
	public void testParseSubjectSuccess() throws Exception {
		//Generate attrDefinitions and pp for setup
		Set<AttributeDefinition> definitions = new HashSet<>();
		definitions.add(new AttributeDefinitionString("uri:Name", "name", 0, 16));
		definitions.add(new AttributeDefinitionBoolean("uri:European", "european"));
		definitions.add(new AttributeDefinitionInteger("uri:Age", "age", 0, 123));
		definitions.add(new AttributeDefinitionInteger("uri:Height", "height", 0, 250));
		definitions.add(new AttributeDefinitionInteger("uri:Weight", "weight", 0, 200));
		definitions.add(new AttributeDefinitionDate("uri:Now", "now", "2015-01-01T00:00:00", "2040-09-01T00:00:00"));
		definitions.add(new AttributeDefinitionDate("uri:DateOfBirth", "dateOfBirth", "1900-01-01T00:00:00", "2100-09-01T00:00:00"));
		Set<String> attrNames=definitions.stream().map(AttributeDefinition::getId).collect(Collectors.toSet());
		OLVerificationLibraryPS library=new OLVerificationLibraryPS();
		PSverfKey key = new PSverfKey(Base64.decodeBase64(key0));
		PSpublicParam params=new PSpublicParam(1,new PSauxArg(PAIRING_NAME,attrNames));
		PabcPublicParameters publicParameters = new PabcPublicParameters(definitions,params.getEncoded());
		library.setup(publicParameters, key, seed);
		// String constant with example presentation and extract subject
		String testPresentation="{\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.org/context\",\"https://olympus-deployment.eu/example/context\"],\"type\":[\"VerifiablePresentation\",\"OlympusPresentation\"],\"expirationDate\":\"2021-06-04T00:00:00\",\"verifiableCredential\":[{\"expirationDate\":\"2021-06-04T00:00:00\",\"issuanceDate\":\"2021-03-17T11:02:35\",\"issuer\":\"did:meta:OL-vIdP\",\"credentialSchema\":[{\"id\":\"https://olympus-project.eu/example/validationSchema\",\"type\":\"OlZkValidationSchema\"},{\"id\":\"https://olympus-project.eu/example/encodingSchema\",\"type\":\"OlZkEncodingSchema\"}],\"credentialSubject\":{\"name\":\"John\",\"european\":true,\"height\":170,\"now\":\"2021-03-23T11:02:00\",\"age\":{\"operation\":\"ge\",\"value\":{\"lowerBound\":18}},\"weight\":{\"operation\":\"inRange\",\"value\":{\"lowerBound\":50,\"upperBound\":90}},\"dateOfBirth\":{\"operation\":\"le\",\"value\":{\"upperBound\":\"2003-03-23T00:00:00\"}}},\"type\":[\"VerifiableCredential\",\"OlympusCredential\"],\"proof\":{\"type\":\"OlPsDerivedProofRange\",\"proofValue\":\"proofValueExample\",\"rangeProofs\":[{\"attr\":\"uri:Height\",\"commitment\":\"commitmentExample\",\"lowerBoundProofValue\":\"lowerProofExample\",\"upperBoundProofValue\":\"upperProofExample\"},{\"attr\":\"uri:Weight\",\"commitment\":\"commitmentExample\",\"lowerBoundProofValue\":\"lowerProofExample\",\"upperBoundProofValue\":\"upperProofExample\"},{\"attr\":\"uri:dateOfBirth\",\"commitment\":\"commitmentExample\",\"lowerBoundProofValue\":\"lowerProofExample\",\"upperBoundProofValue\":\"upperProofExample\"}],\"epoch\":1622764800000,\"proofPurpose\":\"AssertionMethod\",\"nonce\":\"nonceExample2\",\"verificationMethod\":\"verificationMethodExample\"},\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.eu/context\",\"https://olympus-deployment.eu/example/context\"]}]}";
		Map<String, Object> subject = getSubjectFromSerialPresentation(testPresentation);
		//Construct expected results
		Set<Predicate> expectedPreds=new HashSet<>();
		expectedPreds.add(new Predicate("uri:Weight",Operation.INRANGE,new Attribute(50),new Attribute(90)));
		expectedPreds.add(new Predicate("uri:Age",Operation.GREATERTHAN,new Attribute(18)));
		expectedPreds.add(new Predicate("uri:DateOfBirth",Operation.LESSTHAN,new Attribute(Util.fromRFC3339UTC("2003-03-23T00:00:00"))));
		Map<String,Attribute> expectedAttributes=new HashMap<>();
		expectedAttributes.put("uri:Name",new Attribute("John"));
		expectedAttributes.put("uri:European",new Attribute(true));
		expectedAttributes.put("uri:Height",new Attribute(170));
		expectedAttributes.put("uri:Now",new Attribute(Util.fromRFC3339UTC("2021-03-23T11:02:00")));
		// Parse subject
		Pair<Map<String,Attribute>,Set<Predicate>> subjectExtractedInfo=library.parseCredentialSubject(subject);
		// Check results
		assertEquals(subjectExtractedInfo.getFirst(),expectedAttributes);
		assertEquals(subjectExtractedInfo.getSecond(),expectedPreds);
	}

	private Map<String, Object> getSubjectFromSerialPresentation(String testPresentation) {
		VerifiablePresentation reconstructedPresentation = new VerifiablePresentation(Verifiable.getJSONMap(testPresentation));
		VerifiableCredential cred=reconstructedPresentation.getVCCredentials().get(0);
		return cred.obtainCredentialSubject();
	}

	@Test
	public void testParseSubjectFailures() throws Exception{
		//Generate attrDefinitions and pp for setup
		Set<AttributeDefinition> definitions = new HashSet<>();
		definitions.add(new AttributeDefinitionString("uri:Name", "name", 0, 16));
		definitions.add(new AttributeDefinitionBoolean("uri:European", "european"));
		definitions.add(new AttributeDefinitionInteger("uri:Age", "age", 0, 123));
		definitions.add(new AttributeDefinitionInteger("uri:Height", "height", 0, 250));
		definitions.add(new AttributeDefinitionDate("uri:Now", "now", "2015-01-01T00:00:00", "2040-09-01T00:00:00"));
		Set<String> attrNames=definitions.stream().map(AttributeDefinition::getId).collect(Collectors.toSet());
		OLVerificationLibraryPS library=new OLVerificationLibraryPS();
		PSverfKey key = new PSverfKey(Base64.decodeBase64(key0));
		PSpublicParam params=new PSpublicParam(1,new PSauxArg(PAIRING_NAME,attrNames));
		PabcPublicParameters publicParameters = new PabcPublicParameters(definitions,params.getEncoded());
		library.setup(publicParameters, key, seed);
		// No definition for attr name
		String noDefForAttrName="{\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.org/context\",\"https://olympus-deployment.eu/example/context\"],\"type\":[\"VerifiablePresentation\",\"OlympusPresentation\"],\"expirationDate\":\"2021-06-04T00:00:00\",\"verifiableCredential\":[{\"expirationDate\":\"2021-06-04T00:00:00\",\"issuanceDate\":\"2021-03-17T11:02:35\",\"issuer\":\"did:meta:OL-vIdP\",\"credentialSchema\":[{\"id\":\"https://olympus-project.eu/example/validationSchema\",\"type\":\"OlZkValidationSchema\"},{\"id\":\"https://olympus-project.eu/example/encodingSchema\",\"type\":\"OlZkEncodingSchema\"}],\"credentialSubject\":{\"surname\":\"John\",\"european\":true,\"now\":\"2021-03-23T11:02:00\",\"age\":{\"operation\":\"ge\",\"value\":{\"lowerBound\":18}}},\"type\":[\"VerifiableCredential\",\"OlympusCredential\"],\"proof\":{\"type\":\"OlPsDerivedProofRange\",\"proofValue\":\"proofValueExample\",\"rangeProofs\":[{\"attr\":\"uri:Age\",\"commitment\":\"commitmentExample\",\"lowerBoundProofValue\":\"lowerProofExample\",\"upperBoundProofValue\":\"upperProofExample\"}],\"epoch\":1622764800000,\"proofPurpose\":\"AssertionMethod\",\"nonce\":\"nonceExample2\",\"verificationMethod\":\"verificationMethodExample\"},\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.eu/context\",\"https://olympus-deployment.eu/example/context\"]}]}";
		// Invalid Integer, Date, String, Boolean attribute (boolean may not be possible)
		String invalidRevealedInt="{\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.org/context\",\"https://olympus-deployment.eu/example/context\"],\"type\":[\"VerifiablePresentation\",\"OlympusPresentation\"],\"expirationDate\":\"2021-06-04T00:00:00\",\"verifiableCredential\":[{\"expirationDate\":\"2021-06-04T00:00:00\",\"issuanceDate\":\"2021-03-17T11:02:35\",\"issuer\":\"did:meta:OL-vIdP\",\"credentialSchema\":[{\"id\":\"https://olympus-project.eu/example/validationSchema\",\"type\":\"OlZkValidationSchema\"},{\"id\":\"https://olympus-project.eu/example/encodingSchema\",\"type\":\"OlZkEncodingSchema\"}],\"credentialSubject\":{\"name\":\"John\",\"european\":true,\"now\":\"2021-03-23T11:02:00\",\"height\":500,\"age\":{\"operation\":\"ge\",\"value\":{\"lowerBound\":18}}},\"type\":[\"VerifiableCredential\",\"OlympusCredential\"],\"proof\":{\"type\":\"OlPsDerivedProofRange\",\"proofValue\":\"proofValueExample\",\"rangeProofs\":[{\"attr\":\"uri:Age\",\"commitment\":\"commitmentExample\",\"lowerBoundProofValue\":\"lowerProofExample\",\"upperBoundProofValue\":\"upperProofExample\"}],\"epoch\":1622764800000,\"proofPurpose\":\"AssertionMethod\",\"nonce\":\"nonceExample2\",\"verificationMethod\":\"verificationMethodExample\"},\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.eu/context\",\"https://olympus-deployment.eu/example/context\"]}]}";
		String invalidRevealedString="{\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.org/context\",\"https://olympus-deployment.eu/example/context\"],\"type\":[\"VerifiablePresentation\",\"OlympusPresentation\"],\"expirationDate\":\"2021-06-04T00:00:00\",\"verifiableCredential\":[{\"expirationDate\":\"2021-06-04T00:00:00\",\"issuanceDate\":\"2021-03-17T11:02:35\",\"issuer\":\"did:meta:OL-vIdP\",\"credentialSchema\":[{\"id\":\"https://olympus-project.eu/example/validationSchema\",\"type\":\"OlZkValidationSchema\"},{\"id\":\"https://olympus-project.eu/example/encodingSchema\",\"type\":\"OlZkEncodingSchema\"}],\"credentialSubject\":{\"name\":\"John\",\"european\":\"true\",\"now\":\"2021-03-23T11:02:00\",\"height\":180,\"age\":{\"operation\":\"ge\",\"value\":{\"lowerBound\":18}}},\"type\":[\"VerifiableCredential\",\"OlympusCredential\"],\"proof\":{\"type\":\"OlPsDerivedProofRange\",\"proofValue\":\"proofValueExample\",\"rangeProofs\":[{\"attr\":\"uri:Age\",\"commitment\":\"commitmentExample\",\"lowerBoundProofValue\":\"lowerProofExample\",\"upperBoundProofValue\":\"upperProofExample\"}],\"epoch\":1622764800000,\"proofPurpose\":\"AssertionMethod\",\"nonce\":\"nonceExample2\",\"verificationMethod\":\"verificationMethodExample\"},\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.eu/context\",\"https://olympus-deployment.eu/example/context\"]}]}";
		String invalidRevealedBool="{\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.org/context\",\"https://olympus-deployment.eu/example/context\"],\"type\":[\"VerifiablePresentation\",\"OlympusPresentation\"],\"expirationDate\":\"2021-06-04T00:00:00\",\"verifiableCredential\":[{\"expirationDate\":\"2021-06-04T00:00:00\",\"issuanceDate\":\"2021-03-17T11:02:35\",\"issuer\":\"did:meta:OL-vIdP\",\"credentialSchema\":[{\"id\":\"https://olympus-project.eu/example/validationSchema\",\"type\":\"OlZkValidationSchema\"},{\"id\":\"https://olympus-project.eu/example/encodingSchema\",\"type\":\"OlZkEncodingSchema\"}],\"credentialSubject\":{\"name\":true,\"european\":true,\"now\":\"2021-03-23T11:02:00\",\"height\":180,\"age\":{\"operation\":\"ge\",\"value\":{\"lowerBound\":18}}},\"type\":[\"VerifiableCredential\",\"OlympusCredential\"],\"proof\":{\"type\":\"OlPsDerivedProofRange\",\"proofValue\":\"proofValueExample\",\"rangeProofs\":[{\"attr\":\"uri:Age\",\"commitment\":\"commitmentExample\",\"lowerBoundProofValue\":\"lowerProofExample\",\"upperBoundProofValue\":\"upperProofExample\"}],\"epoch\":1622764800000,\"proofPurpose\":\"AssertionMethod\",\"nonce\":\"nonceExample2\",\"verificationMethod\":\"verificationMethodExample\"},\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.eu/context\",\"https://olympus-deployment.eu/example/context\"]}]}";
		String invalidRevealedDate="{\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.org/context\",\"https://olympus-deployment.eu/example/context\"],\"type\":[\"VerifiablePresentation\",\"OlympusPresentation\"],\"expirationDate\":\"2021-06-04T00:00:00\",\"verifiableCredential\":[{\"expirationDate\":\"2021-06-04T00:00:00\",\"issuanceDate\":\"2021-03-17T11:02:35\",\"issuer\":\"did:meta:OL-vIdP\",\"credentialSchema\":[{\"id\":\"https://olympus-project.eu/example/validationSchema\",\"type\":\"OlZkValidationSchema\"},{\"id\":\"https://olympus-project.eu/example/encodingSchema\",\"type\":\"OlZkEncodingSchema\"}],\"credentialSubject\":{\"name\":\"John\",\"european\":true,\"now\":\"2200-03-23T11:02:00\",\"height\":180,\"age\":{\"operation\":\"ge\",\"value\":{\"lowerBound\":18}}},\"type\":[\"VerifiableCredential\",\"OlympusCredential\"],\"proof\":{\"type\":\"OlPsDerivedProofRange\",\"proofValue\":\"proofValueExample\",\"rangeProofs\":[{\"attr\":\"uri:Age\",\"commitment\":\"commitmentExample\",\"lowerBoundProofValue\":\"lowerProofExample\",\"upperBoundProofValue\":\"upperProofExample\"}],\"epoch\":1622764800000,\"proofPurpose\":\"AssertionMethod\",\"nonce\":\"nonceExample2\",\"verificationMethod\":\"verificationMethodExample\"},\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.eu/context\",\"https://olympus-deployment.eu/example/context\"]}]}";
		//Check bad operation
		String badOperationType="{\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.org/context\",\"https://olympus-deployment.eu/example/context\"],\"type\":[\"VerifiablePresentation\",\"OlympusPresentation\"],\"expirationDate\":\"2021-06-04T00:00:00\",\"verifiableCredential\":[{\"expirationDate\":\"2021-06-04T00:00:00\",\"issuanceDate\":\"2021-03-17T11:02:35\",\"issuer\":\"did:meta:OL-vIdP\",\"credentialSchema\":[{\"id\":\"https://olympus-project.eu/example/validationSchema\",\"type\":\"OlZkValidationSchema\"},{\"id\":\"https://olympus-project.eu/example/encodingSchema\",\"type\":\"OlZkEncodingSchema\"}],\"credentialSubject\":{\"name\":\"John\",\"european\":true,\"now\":\"2021-03-23T11:02:00\",\"height\":180,\"age\":{\"operation\":12,\"value\":{\"lowerBound\":18}}},\"type\":[\"VerifiableCredential\",\"OlympusCredential\"],\"proof\":{\"type\":\"OlPsDerivedProofRange\",\"proofValue\":\"proofValueExample\",\"rangeProofs\":[{\"attr\":\"uri:Age\",\"commitment\":\"commitmentExample\",\"lowerBoundProofValue\":\"lowerProofExample\",\"upperBoundProofValue\":\"upperProofExample\"}],\"epoch\":1622764800000,\"proofPurpose\":\"AssertionMethod\",\"nonce\":\"nonceExample2\",\"verificationMethod\":\"verificationMethodExample\"},\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.eu/context\",\"https://olympus-deployment.eu/example/context\"]}]}";
		String badOperationValue="{\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.org/context\",\"https://olympus-deployment.eu/example/context\"],\"type\":[\"VerifiablePresentation\",\"OlympusPresentation\"],\"expirationDate\":\"2021-06-04T00:00:00\",\"verifiableCredential\":[{\"expirationDate\":\"2021-06-04T00:00:00\",\"issuanceDate\":\"2021-03-17T11:02:35\",\"issuer\":\"did:meta:OL-vIdP\",\"credentialSchema\":[{\"id\":\"https://olympus-project.eu/example/validationSchema\",\"type\":\"OlZkValidationSchema\"},{\"id\":\"https://olympus-project.eu/example/encodingSchema\",\"type\":\"OlZkEncodingSchema\"}],\"credentialSubject\":{\"name\":\"John\",\"european\":true,\"now\":\"2021-03-23T11:02:00\",\"height\":180,\"age\":{\"operation\":\"wrong\",\"value\":{\"lowerBound\":18}}},\"type\":[\"VerifiableCredential\",\"OlympusCredential\"],\"proof\":{\"type\":\"OlPsDerivedProofRange\",\"proofValue\":\"proofValueExample\",\"rangeProofs\":[{\"attr\":\"uri:Age\",\"commitment\":\"commitmentExample\",\"lowerBoundProofValue\":\"lowerProofExample\",\"upperBoundProofValue\":\"upperProofExample\"}],\"epoch\":1622764800000,\"proofPurpose\":\"AssertionMethod\",\"nonce\":\"nonceExample2\",\"verificationMethod\":\"verificationMethodExample\"},\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.eu/context\",\"https://olympus-deployment.eu/example/context\"]}]}";
		//Check bad attribute in values (String not parse to date, Boolean)
		String badValueAttributes="{\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.org/context\",\"https://olympus-deployment.eu/example/context\"],\"type\":[\"VerifiablePresentation\",\"OlympusPresentation\"],\"expirationDate\":\"2021-06-04T00:00:00\",\"verifiableCredential\":[{\"expirationDate\":\"2021-06-04T00:00:00\",\"issuanceDate\":\"2021-03-17T11:02:35\",\"issuer\":\"did:meta:OL-vIdP\",\"credentialSchema\":[{\"id\":\"https://olympus-project.eu/example/validationSchema\",\"type\":\"OlZkValidationSchema\"},{\"id\":\"https://olympus-project.eu/example/encodingSchema\",\"type\":\"OlZkEncodingSchema\"}],\"credentialSubject\":{\"name\":\"John\",\"european\":true,\"now\":\"2021-03-23T11:02:00\",\"height\":180,\"age\":{\"operation\":\"ge\",\"value\":{\"lowerBound\":\"2021-06adwqd\"}}},\"type\":[\"VerifiableCredential\",\"OlympusCredential\"],\"proof\":{\"type\":\"OlPsDerivedProofRange\",\"proofValue\":\"proofValueExample\",\"rangeProofs\":[{\"attr\":\"uri:Age\",\"commitment\":\"commitmentExample\",\"lowerBoundProofValue\":\"lowerProofExample\",\"upperBoundProofValue\":\"upperProofExample\"}],\"epoch\":1622764800000,\"proofPurpose\":\"AssertionMethod\",\"nonce\":\"nonceExample2\",\"verificationMethod\":\"verificationMethodExample\"},\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.eu/context\",\"https://olympus-deployment.eu/example/context\"]}]}";
		//Check values not present
		String noValues="{\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.org/context\",\"https://olympus-deployment.eu/example/context\"],\"type\":[\"VerifiablePresentation\",\"OlympusPresentation\"],\"expirationDate\":\"2021-06-04T00:00:00\",\"verifiableCredential\":[{\"expirationDate\":\"2021-06-04T00:00:00\",\"issuanceDate\":\"2021-03-17T11:02:35\",\"issuer\":\"did:meta:OL-vIdP\",\"credentialSchema\":[{\"id\":\"https://olympus-project.eu/example/validationSchema\",\"type\":\"OlZkValidationSchema\"},{\"id\":\"https://olympus-project.eu/example/encodingSchema\",\"type\":\"OlZkEncodingSchema\"}],\"credentialSubject\":{\"name\":\"John\",\"european\":true,\"now\":\"2021-03-23T11:02:00\",\"height\":180,\"age\":{\"operation\":\"ge\"}},\"type\":[\"VerifiableCredential\",\"OlympusCredential\"],\"proof\":{\"type\":\"OlPsDerivedProofRange\",\"proofValue\":\"proofValueExample\",\"rangeProofs\":[{\"attr\":\"uri:Age\",\"commitment\":\"commitmentExample\",\"lowerBoundProofValue\":\"lowerProofExample\",\"upperBoundProofValue\":\"upperProofExample\"}],\"epoch\":1622764800000,\"proofPurpose\":\"AssertionMethod\",\"nonce\":\"nonceExample2\",\"verificationMethod\":\"verificationMethodExample\"},\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.eu/context\",\"https://olympus-deployment.eu/example/context\"]}]}";
		//Check values cast exception
		String badValues="{\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.org/context\",\"https://olympus-deployment.eu/example/context\"],\"type\":[\"VerifiablePresentation\",\"OlympusPresentation\"],\"expirationDate\":\"2021-06-04T00:00:00\",\"verifiableCredential\":[{\"expirationDate\":\"2021-06-04T00:00:00\",\"issuanceDate\":\"2021-03-17T11:02:35\",\"issuer\":\"did:meta:OL-vIdP\",\"credentialSchema\":[{\"id\":\"https://olympus-project.eu/example/validationSchema\",\"type\":\"OlZkValidationSchema\"},{\"id\":\"https://olympus-project.eu/example/encodingSchema\",\"type\":\"OlZkEncodingSchema\"}],\"credentialSubject\":{\"name\":\"John\",\"european\":true,\"now\":\"2021-03-23T11:02:00\",\"height\":180,\"age\":{\"operation\":\"ge\",\"value\":\"asd\"}},\"type\":[\"VerifiableCredential\",\"OlympusCredential\"],\"proof\":{\"type\":\"OlPsDerivedProofRange\",\"proofValue\":\"proofValueExample\",\"rangeProofs\":[{\"attr\":\"uri:Age\",\"commitment\":\"commitmentExample\",\"lowerBoundProofValue\":\"lowerProofExample\",\"upperBoundProofValue\":\"upperProofExample\"}],\"epoch\":1622764800000,\"proofPurpose\":\"AssertionMethod\",\"nonce\":\"nonceExample2\",\"verificationMethod\":\"verificationMethodExample\"},\"@context\":[\"https://w3id.org/credentials/v1\",\"https://olympus-project.eu/context\",\"https://olympus-deployment.eu/example/context\"]}]}";
		assertNull(library.parseCredentialSubject(getSubjectFromSerialPresentation(noDefForAttrName)));
		assertNull(library.parseCredentialSubject(getSubjectFromSerialPresentation(invalidRevealedInt)));
		assertNull(library.parseCredentialSubject(getSubjectFromSerialPresentation(invalidRevealedString)));
		assertNull(library.parseCredentialSubject(getSubjectFromSerialPresentation(invalidRevealedBool)));
		assertNull(library.parseCredentialSubject(getSubjectFromSerialPresentation(invalidRevealedDate)));
		assertNull(library.parseCredentialSubject(getSubjectFromSerialPresentation(badOperationType)));
		assertNull(library.parseCredentialSubject(getSubjectFromSerialPresentation(badOperationValue)));
		assertNotNull(library.parseCredentialSubject(getSubjectFromSerialPresentation(badValueAttributes)));
		assertNull(library.parseCredentialSubject(getSubjectFromSerialPresentation(noValues)));
		assertNull(library.parseCredentialSubject(getSubjectFromSerialPresentation(badValues)));
	}

	@Test(expected = RuntimeException.class)
	public void testVerifierBadConstructor() throws Exception {
		List<PestoIdPImpl> servers = new LinkedList<>();
		servers.add(new PestoIdPImpl(new InMemoryPestoDatabase(), null, new HashMap<String, MFAAuthenticator>(), null) {
			@Override
			public PabcPublicParameters getPabcPublicParam() {
				MSpublicParam param = new MSpublicParam() {

					@Override
					public int getN() {
						return 0;
					}

					@Override
					public MSauxArg getAuxArg() {
						return new PSauxArg("pairingName", new HashSet<String>());
					}

					@Override
					public String getEncoded() {
						return "WrongEncoded";
					}
				};
				return new PabcPublicParameters(new HashSet<>(), param.getEncoded());
			}
		});
		OLVerificationLibraryPS credentialVerifierModule = new OLVerificationLibraryPS();
		credentialVerifierModule.setup(servers, seed);
		fail("Should throw RuntimeException");
	}

	@Test
	public void testVerifierSetupExceptions() throws Exception {
		MSpublicParam mockPublicParam = new MockPublicParam();
		Set<String> attr = new HashSet<>();
		attr.add("test");
		MSpublicParam wrongPublicParam = new PSpublicParam(1, new PSauxArg("WrongPairingName", attr));
		OLVerificationLibraryPS credentialVerifierModule = new OLVerificationLibraryPS();
		MSpublicParam differentAttrPublicParam = new PSpublicParam(1, new PSauxArg("eu.olympus.util.pairingBLS461.PairingBuilderBLS461", attr));
		try {
			credentialVerifierModule.setup(new PabcPublicParameters(generateAttributeDefinitions(), differentAttrPublicParam.getEncoded()), null, seed);
			fail("Should throw IllegalArgumentException, conflictingAttr");
		} catch (IllegalArgumentException e) {
		}
		try {
			credentialVerifierModule.setup(new PabcPublicParameters(generateAttributeDefinitions(), "ExtraWrong" + wrongPublicParam.getEncoded()), null, seed);
			fail("Should throw IllegalArgumentException, wrongPublicParam");
		} catch (IllegalArgumentException e) {
		}
		try {
			credentialVerifierModule.setup(new PabcPublicParameters(new HashSet<>(), wrongPublicParam.getEncoded()), null, seed);
			fail("Should throw MSSetupException");
		} catch (MSSetupException e) {
		}
	}

	@Test()
	public void testOlPSLibraryMethodsNoSetup()  {
		OLVerificationLibraryPS verifier = new OLVerificationLibraryPS();
		Set<Predicate> predicates = new HashSet<>();
		predicates.add(new Predicate("Age", Operation.GREATERTHAN, new Attribute(18)));
		try{
			verifier.verifyOlPsDerivedProof("testToken", new HashMap<>(),"nonce",123);
			fail();
		}catch (IllegalStateException e){
		}
		try{
			verifier.verifyOlPsDerivedProofRange("testToken", new HashMap<>(),new HashMap<>(), predicates,"nonce",123);
			fail();
		}catch (IllegalStateException e){
		}
	}

	@Test()
	public void testWrongAttributes() throws Exception {
		Set<AttributeDefinition> definitions = new HashSet<>();
		definitions.add(new AttributeDefinitionString("uri:Name", "name", 0, 16));
		definitions.add(new AttributeDefinitionBoolean("uri:European", "european"));
		definitions.add(new AttributeDefinitionInteger("uri:Age", "age", 0, 123));
		Set<String> attrNames=definitions.stream().map(AttributeDefinition::getId).collect(Collectors.toSet());
		OLVerificationLibraryPS library=new OLVerificationLibraryPS();
		PSverfKey key = new PSverfKey(Base64.decodeBase64(key0));
		PSpublicParam params=new PSpublicParam(1,new PSauxArg(PAIRING_NAME,attrNames));
		PabcPublicParameters publicParameters = new PabcPublicParameters(definitions,params.getEncoded());
		library.setup(publicParameters, key, seed);
		Map<String, Attribute> attr=new HashMap<>();
		attr.put("uri:Wrong", new Attribute(2));
		assertThat(library.verifyOlPsDerivedProof(TEST_TOKEN,attr,"nonce",123),is(OLVerificationLibraryResult.INVALID_ATTRIBUTES));
	}

	@Test()
	public void testWrongAttributesRange() throws Exception {
		Set<AttributeDefinition> definitions = new HashSet<>();
		definitions.add(new AttributeDefinitionString("uri:Name", "name", 0, 16));
		definitions.add(new AttributeDefinitionBoolean("uri:European", "european"));
		definitions.add(new AttributeDefinitionInteger("uri:Age", "age", 0, 123));
		Set<String> attrNames=definitions.stream().map(AttributeDefinition::getId).collect(Collectors.toSet());
		OLVerificationLibraryPS library=new OLVerificationLibraryPS();
		PSverfKey key = new PSverfKey(Base64.decodeBase64(key0));
		PSpublicParam params=new PSpublicParam(1,new PSauxArg(PAIRING_NAME,attrNames));
		PabcPublicParameters publicParameters = new PabcPublicParameters(definitions,params.getEncoded());
		library.setup(publicParameters, key, seed);
		Map<String, Attribute> wrongAttr=new HashMap<>();
		wrongAttr.put("uri:Wrong", new Attribute(2));
		Map<String, RangePredicateToken> wrongTokenMap=new HashMap<>();
		wrongTokenMap.put("uri:Wrong", new RangePredicateToken((RangeProof) null,null,null));
		Map<String, Attribute> goodAttr=new HashMap<>();
		goodAttr.put("uri:Name", new Attribute(2));
		Map<String, RangePredicateToken> goodTokenMap=new HashMap<>();
		goodTokenMap.put("uri:Age", new RangePredicateToken((RangeProof) null,null,null));
		assertThat(library.verifyOlPsDerivedProofRange(TEST_RANGE_TOKEN,wrongAttr,goodTokenMap,new HashSet<>(),"nonce",123),is(OLVerificationLibraryResult.INVALID_ATTRIBUTES));
		assertThat(library.verifyOlPsDerivedProofRange(TEST_RANGE_TOKEN,goodAttr,wrongTokenMap,new HashSet<>(),"nonce",123),is(OLVerificationLibraryResult.INVALID_ATTRIBUTES));
		assertThat(library.verifyOlPsDerivedProofRange(TEST_RANGE_TOKEN,goodAttr,goodTokenMap,new HashSet<>(),"nonce",123),is(OLVerificationLibraryResult.INVALID_SIGNATURE));
	}

	private Set<AttributeDefinition> generateAttributeDefinitions() {
		Set<AttributeDefinition> res=new HashSet<>();
		res.add(new AttributeDefinitionString("Name","Name",0,16));
		res.add(new AttributeDefinitionInteger("Age","Age",0,123));
		res.add(new AttributeDefinitionDate("Now","Now","1900-01-01T00:00:00","2100-09-01T00:00:00"));
		return res;
	}

	@Test(expected = RuntimeException.class)
	public void testSetupBadInput() throws Exception {
		PestoDatabase db = new InMemoryPestoDatabase();
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(1));
		
		List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
		idps.add(new PestoIdPImpl(db, null, new HashMap<String, MFAAuthenticator>(), cm) {
			@Override
			public PabcPublicParameters getPabcPublicParam() {
				return new PabcPublicParameters(new HashSet<>(),"Wrong");
			}
		});
		OLVerificationLibraryPS verifier = new OLVerificationLibraryPS();
		verifier.setup(idps,seed);
	}


	@Test(expected = RuntimeException.class)
	public void testSetupWrongSchemeName() throws Exception {
		PestoDatabase db = new InMemoryPestoDatabase();
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(1));

		List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
		idps.add(new PestoIdPImpl(db, null,null, cm) {
			@Override
			public PabcPublicParameters getPabcPublicParam() {
				MSpublicParam params=new PSpublicParam(1,new PSauxArg("WrongName",new HashSet<>()));
				return new PabcPublicParameters(new HashSet<>(),params.getEncoded());
			}
		});
		OLVerificationLibraryPS verifier = new OLVerificationLibraryPS();
		verifier.setup(idps,seed);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSetupConflictingAttributeNames() throws Exception {
		PestoDatabase db = new InMemoryPestoDatabase();
		ServerCryptoModule cm = new SoftwareServerCryptoModule(new Random(1));

		List<PestoIdPImpl> idps = new ArrayList<PestoIdPImpl>();
		idps.add(new PestoIdPImpl(db, null,null, cm) {
			@Override
			public PabcPublicParameters getPabcPublicParam() {
				return new PabcPublicParameters(new HashSet<>(),param);
			}
		});
		OLVerificationLibraryPS verifier = new OLVerificationLibraryPS();
		verifier.setup(idps,seed);
	}

}
