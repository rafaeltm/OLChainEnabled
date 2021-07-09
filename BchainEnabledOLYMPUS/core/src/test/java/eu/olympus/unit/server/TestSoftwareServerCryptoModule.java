package eu.olympus.unit.server;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.apache.commons.codec.binary.Base64;
import org.hamcrest.core.IsInstanceOf;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import eu.olympus.model.KeyShares;
import eu.olympus.model.RSASharedKey;
import eu.olympus.server.SoftwareServerCryptoModule;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.ECP2;
import org.miracl.core.BLS12461.FP12;

public class TestSoftwareServerCryptoModule {
	@Rule
	public final ExpectedException exception = ExpectedException.none();
	
	SoftwareServerCryptoModule crypto = null;
	private final BigInteger di = new BigInteger("134171036063420089132872"
			+ "78998879458815400829591316836928871131626762792189422272857"
			+ "39766306178097453396797222594830828154957349985496003186836"
			+ "61439705716521059523817881643085878539124280284350447235645"
			+ "26781091011151768131157594160400363891212748601483628315961"
			+ "32306609127009642600962633970885442844230826646929641795406"
			+ "96499685179492276066597865791570778369148199182140087330540"
			+ "83653808971577967725166316654083363488068435935252850459733"
			+ "75958313602839877754183485323564713395515815547205098981076"
			+ "06123369144556816276221976832706718009780285794778766329126"
			+ "71092450589613312840441605621432803632699380444350433080962"
			+ "505");
	private final BigInteger modulus = new BigInteger("1692653793237283178"
			+ "02095979470165564762540986145283170380070329250448153326949"
			+ "02620941127722957895783030645359332697065350909516256222749"
			+ "39954786381642292178998250679033136907201643648185142250141"
			+ "57779435918374097259509906191697335879160010473715585561329"
			+ "17730028100298823236433259405983281664568650475598367869076"
			+ "30285969138714777606722811345389631922951468015303013611718"
			+ "46218097014429092089680883412967387138413337923553586431481"
			+ "57170767560339357020918008852864926335997159916869547088339"
			+ "14319460219856455867125987074077998909016307802570248407193"
			+ "03331855604730713974984313369625580744252999429176146016735"
			+ "83116227");
	private final BigInteger exponent = new BigInteger("65537");

	@Test
	public void testSetup() {
		RSASharedKey key = new RSASharedKey(modulus, di, exponent);
		BigInteger b1 = new BigInteger("13417103606342");
		BigInteger b2 = new BigInteger("13417103606343");
		Map<Integer, BigInteger> rsaBlindings = new HashMap<>();
		rsaBlindings.put(1, b1); rsaBlindings.put(2, b2);

		BigInteger oprfKey = new BigInteger("42");
		BigInteger s1 = new BigInteger("13417103606345");
		BigInteger s2 = new BigInteger("13417103606346");
		Map<Integer, BigInteger> oprfBlindings = new HashMap<>();
		oprfBlindings.put(1, s1); oprfBlindings.put(2, s2);

		crypto = new SoftwareServerCryptoModule(new Random(0));
		boolean complete = crypto.setupServer(new KeyShares(key, rsaBlindings, oprfKey, oprfBlindings));
		assertTrue(complete);
	}
	
	@Ignore
	@Test
	public void testSetupBadKey() {
		BigInteger modulus = new BigInteger("1692653793237283178020959794701655647625409861452831703"
				+ "80070329250448153326949026209411277229578957830306453593326970653509095162562227493995478"
				+ "63816422921789982506790331369072016436481851422501415777943591837409725950990619169733587"
				+ "91600104737155855613291773002810029882323643325940598328166456865047559836786907630285969"
				+ "13871477760672281134538963192295146801530301361171846218097014429092089680883412967387138"
				+ "41333792355358643148157170767560339357020918008852864926335997159916869547088339143194602"
				+ "19856455867125987074077998909016307802570248407193033318556047307139749843133696255807442"
				+ "5299942917614601673583116227");
		BigInteger di = new BigInteger(1, modulus.toByteArray());
		BigInteger exponent = new BigInteger("65537");
		RSASharedKey key = new RSASharedKey(modulus, di, exponent);
		BigInteger b0 = new BigInteger("13417103606341");
		BigInteger b1 = new BigInteger("13417103606342");
		BigInteger b2 = new BigInteger("13417103606343");
		Map<Integer, BigInteger> rsaBlindings = new HashMap<>();
		rsaBlindings.put(0, b0); rsaBlindings.put(1, b1); rsaBlindings.put(2, b2);

		// Modulus is going to be too big
		BigInteger oprfKey = new BigInteger(1, modulus.toByteArray());
		BigInteger s0 = new BigInteger("13417103606344");
		BigInteger s1 = new BigInteger("13417103606345");
		BigInteger s2 = new BigInteger("13417103606346");
		Map<Integer, BigInteger> oprfBlindings = new HashMap<>();
		oprfBlindings.put(0, s0); oprfBlindings.put(1, s1); oprfBlindings.put(2, s2);

		crypto = new SoftwareServerCryptoModule(new Random(0));
		boolean complete = crypto.setupServer(new KeyShares(null, rsaBlindings, oprfKey, oprfBlindings));
		assertFalse(complete);
	}
	
	@Test
	public void testSignature() throws Exception {
		if(crypto == null) {
			testSetup();
		}
		KeyFactory kf = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(modulus, exponent);
		PublicKey publicKey = kf.generatePublic(pubSpec);
		byte[] salt = "salt".getBytes();
		
		byte[] signature = crypto.sign(publicKey, salt, 0);
		String correctSignature = "NAfa0ZByHyMkwdK5pHCoeaMInFfQJUo8EGhAjiP"
				+ "3Kj5jW0JL1tXNoHefXw9v1GYKoG+2hQ6yBsG97cwNK4jQ1JYCU2L8qP"
				+ "mZZjP+xZ/kBfYrMrOpamervh2CeAVHwbqQyhB4+hGrFSy4Er/2dMz8p"
				+ "YePQHGzsIkdKlqLXHJIJICj++KysF+qGgbkqaBWNHyXb/SZjsTSo9ev"
				+ "YVDWg8GWcRDM8sHyslUcXRH4/ENvw0je91V5eKeQCCV51BLKbEjggCE"
				+ "4GMZuP9ofKjpzbkCyf47l+AUvcFf31kaac9It5pPa4xymXExQbDuHFn"
				+ "1NZJ8RXZdFgPsoPAxck3B9tnjXvQ==";
		assertEquals(correctSignature, Base64.encodeBase64String(signature));
	}
	
	@Test
	public void verifyRSASignaure() throws Exception {
		if(crypto == null) {
			testSetup();
		}
		KeyFactory kf = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(modulus, exponent);
		PublicKey publicKey = kf.generatePublic(pubSpec);
		List<byte[]> message = new ArrayList<byte[]>();
		message.add("salt".getBytes());
		message.add("M1".getBytes());
		
		
		String signature = "KPWUAxTpHWNYzsR3p5FggGSdMCvl2fOgB8Peep2"
				+ "ICXPU72K0LGIAxn79jTWFcWjnA0HQRrOMHKZO+K93WkEU27gDA4lOK/"
				+ "0nVGjqa+9eofOcobqONT2f/3jemZFAvh/OUMLT0JRtbQKb6IIWsEsZX"
				+ "TSvdOcMP/bVF8yjVTKs8nrhg8DsWHJxOq3XD4/8gxDrTwAguz7AMXnh"
				+ "CxOZ0k9N/l0z+SICyzR5bKUw6ZXD/4S4Iwl7J4fAMZ2TPxHVX+/7NM8"
				+ "TqW6o6pGcNSwPklTzcl0W1+yt5HYhK31n92ATvNcWbVnEpEIjrkS6cY"
				+ "2zIkjd7/OWqZEN7pK6IJlu+taC9A==";
		
		boolean valid = crypto.verifySignature(publicKey, message, Base64.decodeBase64(signature));
		
		assertTrue(valid);
	}
	
	@Ignore
	@Test
	public void verifyECSignaure() throws Exception {
		if(crypto == null) {
			testSetup();
		}
		KeyFactory kf = KeyFactory.getInstance("EC");
		RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(modulus, exponent);
		PublicKey publicKey = kf.generatePublic(pubSpec);
		List<byte[]> message = new ArrayList<byte[]>();
		message.add("salt".getBytes());
		message.add("M1".getBytes());
		
		
		String signature = "KPWUAxTpHWNYzsR3p5FggGSdMCvl2fOgB8Peep2"
				+ "ICXPU72K0LGIAxn79jTWFcWjnA0HQRrOMHKZO+K93WkEU27gDA4lOK/"
				+ "0nVGjqa+9eofOcobqONT2f/3jemZFAvh/OUMLT0JRtbQKb6IIWsEsZX"
				+ "TSvdOcMP/bVF8yjVTKs8nrhg8DsWHJxOq3XD4/8gxDrTwAguz7AMXnh"
				+ "CxOZ0k9N/l0z+SICyzR5bKUw6ZXD/4S4Iwl7J4fAMZ2TPxHVX+/7NM8"
				+ "TqW6o6pGcNSwPklTzcl0W1+yt5HYhK31n92ATvNcWbVnEpEIjrkS6cY"
				+ "2zIkjd7/OWqZEN7pK6IJlu+taC9A==";
		
		boolean valid = crypto.verifySignature(publicKey, message, Base64.decodeBase64(signature));
		
		assertTrue(valid);
	}
	
	@Test
	public void verifySignatureException() throws Exception {
		if(crypto == null) {
			testSetup();
		}
		PublicKey publicKey = null;
		
		List<byte[]> message = new ArrayList<byte[]>();
		message.add("salt".getBytes());
		message.add("M1".getBytes());
		
		
		String signature = "KPWUAxTpHWNYzsR3p5FggGSdMCvl2fOgB8Peep2"
				+ "ICXPU72K0LGIAxn79jTWFcWjnA0HQRrOMHKZO+K93WkEU27gDA4lOK/"
				+ "0nVGjqa+9eofOcobqONT2f/3jemZFAvh/OUMLT0JRtbQKb6IIWsEsZX"
				+ "TSvdOcMP/bVF8yjVTKs8nrhg8DsWHJxOq3XD4/8gxDrTwAguz7AMXnh"
				+ "CxOZ0k9N/l0z+SICyzR5bKUw6ZXD/4S4Iwl7J4fAMZ2TPxHVX+/7NM8"
				+ "TqW6o6pGcNSwPklTzcl0W1+yt5HYhK31n92ATvNcWbVnEpEIjrkS6cY"
				+ "2zIkjd7/OWqZEN7pK6IJlu+taC9A==";
		
		boolean valid = crypto.verifySignature(publicKey, message, Base64.decodeBase64(signature));
		assertFalse(valid);
	}
	
	
	@Test
	public void verifyBadSignaure() throws Exception {
		if(crypto == null) {
			testSetup();
		}
		KeyFactory kf = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(modulus, exponent);
		PublicKey publicKey = kf.generatePublic(pubSpec);
		List<byte[]> message = new ArrayList<byte[]>();
		message.add("salt".getBytes());
		message.add("M1".getBytes());
		
		
		String signature = "KPWUAxTpHWNYzsR3p5FggGSdMCvl2fOgB8Peep2"
				+ "ICXPU72K0LGIAxn79jTWFcWjnA0HQRrOMHKZO+K93WkEU27gDA4lOK/"
				+ "0nVGjqa+9eofOcobqONT2f/3jemZFAvh/OUMLT0JRtbQKb6IIWsEsZX"
				+ "TSvdOcMP/bVF8yjVTKs8nrhg8DsWHJxOq3XD4/8gxDrTwAguz7AMXnh"
				+ "CxOZ0k9N/l0z+SICyzR5bKUw6ZXD/4S4Iwl7J4fAMZ2TPxHVX+/7NM8"
				+ "TqW6o6pGcNSwPklTzcl0W1+yt5HYhK31n92ATvNcWbVnEpEIjrkS6cY"
				+ "2zIkjd7/OWqZEN7pK6IJlu+taB9A==";
		
		boolean valid = crypto.verifySignature(publicKey, message, Base64.decodeBase64(signature));
		assertFalse(valid);
	}
	
	@Test
	public void testGetBytes() {
		if(crypto == null) {
			testSetup();
		}
		assertEquals(32, crypto.getBytes(32).length);
		assertEquals(1, crypto.getBytes(1).length);
		assertEquals(256, crypto.getBytes(256).length);
		assertEquals(257, crypto.getBytes(257).length);
	}

	@Test
	public void testHashToGroupElement() {
		if(crypto == null) {
			testSetup();
		}
		ECP ecp = crypto.hashToGroup1Element("inputValue".getBytes());

		byte[] bytes = new byte[117]; 
		ecp.toBytes(bytes, false);
		String expected = "BAwmBOJCKqWGfmPLQ2YsZ7B/xbKh0usSQuwPGfaQIdVVxxXlm" +
				"zoIK1+AJ6VcygGK9HCFsKn+TG1Z4REM3oYHao+Be6c8aSrBLWZHHOZ3vEka" +
				"hnUHjXca41HTvOabrym0KzV/BX5gs98YqdJSbVT+O/HgGwi4";
 		assertEquals(expected, b64(bytes));
	}
	
	@Test
	public void testCombineSignatures() throws Exception {
		if(crypto == null) {
			testSetup();
		}
		BigInteger s1 = new BigInteger("1000");
		BigInteger s2 = new BigInteger("3000");
		BigInteger s3 = new BigInteger("2");
		List<byte[]> partialSignatures = new ArrayList<byte[]>();
		partialSignatures.add(s1.toByteArray());
		byte[] signature = crypto.combineSignatures(partialSignatures);
		assertEquals( new BigInteger("1000"), new BigInteger(signature));
		
		partialSignatures.add(s2.toByteArray());
		signature = crypto.combineSignatures(partialSignatures);
		assertEquals( new BigInteger("3000000"), new BigInteger(signature));
		
		partialSignatures.add(s3.toByteArray());
		signature = crypto.combineSignatures(partialSignatures);
		assertEquals( new BigInteger("6000000"), new BigInteger(signature));
	}
	
	@Test
	public void testGetStandardRSAKey() throws Exception {
		if(crypto == null) {
			testSetup();
		}
		RSAPublicKey pk = (RSAPublicKey)crypto.getStandardRSAkey();
		
		assertEquals(exponent, pk.getPublicExponent());
		assertEquals(modulus, pk.getModulus());
	}
	
	@Test
	public void testHash() throws Exception {
		if(crypto == null) {
			testSetup();
		}
		List<byte[]> values = new ArrayList<byte[]>();
		values.add("value1".getBytes());
		values.add("value2".getBytes());
		byte[] hash = crypto.hash(values);
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		
		md.update(values.get(0));
		md.update(values.get(1));
		byte[] h2 = md.digest();
		assertEquals(b64(hash), b64(h2));
	}
	
	
	@Test
	public void testConstructNonce() throws Exception {
		if(crypto == null) {
			testSetup();
		}
		byte[] nonce1 = crypto.constructNonce("user1", 1000);
		byte[] nonce2 = crypto.constructNonce("user1", 1000);
		byte[] nonce3 = crypto.constructNonce("user2", 1000);
		byte[] nonce4 = crypto.constructNonce("user1", 2000);
		assertEquals(b64(nonce1), b64(nonce2));
		assertNotEquals(b64(nonce2), b64(nonce3));
		assertNotEquals(b64(nonce2), b64(nonce4));
	}
	
	@Test
	public void testGetRandomNumer() {
		if(crypto == null) {
			testSetup();
		}
		BIG rnd = crypto.getRandomNumber();
		assertThat(rnd, IsInstanceOf.instanceOf(BIG.class));
	}
	
	@Test
	public void testGetModulus() {
		if(crypto == null) {
			testSetup();
		}
		BigInteger mod = crypto.getModulus();
		assertEquals(modulus, mod);
	}
	
	@Test
	public void testHashAndPair() {
		if(crypto == null) {
			testSetup();
		}
		ECP point = ECP.generator();
		FP12 fp = crypto.hashAndPair("inputValue".getBytes(), point);
		byte[] bytes = new byte[696]; 
		fp.toBytes(bytes);
		String expected = "BjJlmm9TPJaMLqIzvsAvgZynah8VQvudJIoc+NkK0YM5HouW52pufawgwokS1rLnH/lfxhwRTs3+P" +
				"AGvKeQ8rO7TIFlSFZKh6prWcYjVfTzksriz8M2FAIyJNZpb4u7ap2dtkOGMgoQIcSX/8iLbuSDb860HTb07xSgo" +
				"mNOnQ7B0wbZ2dQvQDdKTXo9NKmKMWZl7FzTD77VWHjFQB/BPAV7XCtnpamxuM38gEFYmARoZOAS7xP9whxkVlyY" +
				"DcNIbv2Q8Aks2aovfUrODvy2SxOw/CEGnX4QiNjs95I5vMgxCad/PQUNiUQziNBFM+dc0BUGUtp4TGgg8gHwaTB" +
				"RccuV0JI7Vjmd3XTQBJfF8P4B4mqrXbmiQS1hfPs4dCUi0dP0BuC/LncIiA/OmgLXhdQ/CfieQZqWqW515QPks5" +
				"1QBaYHDI9anFyoXBp/S3rzc5P984Qd7AHOZCvBtE/GlO3JGjNkokyA+wCdtwraG6bm5GO/oenfKizW6RsE0nkyk" +
				"ykhU3CyBWVhQ1XKP5iMLnPDWiDGXlQwE8SO5n6l6T97atiDWx+FF5DC1JvFlgV6gFNMaoQ8dC62zSrGk1VWbc5F" +
				"UwRumfuNGKBzqF+Cy5JgAFnuE06586VHSuUcqP5xW0bORQ7qpw9ZLLCel4hYAzl69y/WepfxBJJrOhUspY3h0OK" +
				"MN/sotqMeLCRNXPagdJeUKEuR/ujWd+vFpGZ19ESOYUaY2pLWjh2akYn/qBqPCJNFvxcEBVY8MsaMlm56qdB0XP" +
				"BFD4VPfeCaImLD0sRbIi61K7UAxDDZcyznu4FmlfImY++9kq3RZxG+G36Wby+8hHtd4S1shjCU/IH8PyvPtiRUc" +
				"FyWY6N4BDS617u46nbNKCZt9d7uaypTH15GvBNh7jLjoeaii54/BZ+moT0WgHH2Wc+yc";
		assertEquals(expected, b64(bytes));
	}
	
	@Test
	public void testGenerateBlinding() {
		if(crypto == null) {
			testSetup();
		}

		FP12 fp = crypto.generateBlinding("ssid", 0);

		byte[] bytes = new byte[696]; 
		fp.toBytes(bytes);
		String expected = "DdH3mbsYXKObEtgee5VoucjywUoGFcHpIcgPxdguePPPAsjhM2uf1md5dsMjlwfCKHmOQHV/jsxF" +
				"Ig/8aeZDdftgqTcc0ARIAEWknbvhDElHFaE5QtIeRTX9vr0spW7uIT6qFL+YyvfPvbE8lMg0DNhtvPQVKPR9FR" +
				"Gkb+13M5eKxFwB61WdRu0R7ADTc9ehUvorqEQAVwH3dBQlReU442uHUXBM2d5OVdE9UXIbEsqn4dr8PmG6XfzU" +
				"ybyDoxVRIUwieap+d48QHu0OYIDwiHYBQOlY/ebNnQITxVRQqsVpj9uR5XWE6wN+NgpmfFCC2rCrRewsyaz0jL" +
				"GHF2Rb5ujuQ2vA2kPIQg/SiVK/o1+1r4tr4jFOMUF1/h5Zd7GcxZsU4erXatDbTK68afGlKy+ve5O+2F+jD1iW" +
				"sGyvoSqsBW6VMXVbhIzv2qq0hjdsmtaOhaWzufbhXxxHARUQpYX9bjCWn4N0ZtitogZejejJYqXhxUD7am2nDp" +
				"xe6Xd5StsJI6jQITWEKq+0O0SbdNSvE+PCahMERUCJPF4zcMulvKTZ33CQ4QJe5jg6HPjCBjL8G/qpP5HtfoBq" +
				"eh0hk8hLkUHLsTSmP7w0WZpL5pQBJ6vr5b0oFRUND9/yp5bgp42s+FaFdTL61e5zR4goYNdyDYtPLC6Qcx2o4V" +
				"ozCasheS6BK74qzFsdCG1WyDSs1P0CtKacdI3LfDoeXiVtxwLOw2TtKNEZraDXblVeJ1nAsUU5zVMB9/9o9w08" +
				"MYb04UbgSRCiPQB9FkZlJUUgKqV86LGs83MlH983N4lYPVLjA7mdlOWzktV3sG3RNacDGV0M8roBRB5urHKIG5" +
				"8EckYueeEWsNCdwZfYhy5tMYp4VWNC/ucwChBradXKvEZtNLR7ctsge21ZTWDQdVNczMNSiq/Y6sNP";
		assertEquals(expected, b64(bytes));
	}

	@Test
	public void sanityCheckCurveHashing() {
		if(crypto == null) {
			testSetup();
		}
		ECP point = crypto.hashToGroup1Element("something".getBytes());
		assertThat(point.is_infinity(), is(false));
		ECP2 point2 = crypto.hashToGroup2("something".getBytes());
		assertThat(point2.is_infinity(), is(false));
	}

	@Test
	public void sanityCheckCurveOperations() {
		if(crypto == null) {
			testSetup();
		}
		ECP point = crypto.hashToGroup1Element("something".getBytes());
		FP12 fp12 = crypto.hashAndPair("something else".getBytes(), point);
		FP12 zero = new FP12();
		zero.zero();
		FP12 one = new FP12();
		one.one();
		assertThat(fp12.equals(one), is(false));
	}
	
	private String b64(byte[] input) {
		return Base64.encodeBase64String(input);
	}
	
}
