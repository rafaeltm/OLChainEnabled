package eu.olympus.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.apache.commons.codec.binary.Base64;
import org.hamcrest.core.IsInstanceOf;
import org.junit.Test;

import eu.olympus.TestParameters;
import eu.olympus.client.SoftwareClientCryptoModule;
import eu.olympus.client.interfaces.ClientCryptoModule;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.ECP;

public class TestSoftwareClientCryptoModule {

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
	public void testSign() throws Exception {
		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new Random(0), modulus);
		List<byte[]> message = new ArrayList<>();
		message.add("message".getBytes());
		byte[] signature = crypto.sign(TestParameters.getECPrivateKey1(), message);
		
		Signature sig = Signature.getInstance("SHA256withECDSA");
		sig.initVerify(TestParameters.getECPublicKey1());
		for(byte[] bytes: message) {
			sig.update(bytes);
		}
		assertTrue(sig.verify(signature));
	}
	
	@Test
	public void verifyRSASignaure() throws Exception {
		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new Random(0), modulus);
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
		
	@Test
	public void verifyECSignaure() throws Exception {
		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new Random(0), modulus);
		
		List<byte[]> message = new ArrayList<byte[]>();
		message.add("salt".getBytes());
		message.add("M1".getBytes());

		String signature = "MEUCIQDgBr+QnM9MsEz7wpvvqwDlBOrmZcEARjgPre61F4"
				+ "NsJAIgQJGz2Pl9Bc5BOg+XQFBQ0rLmufvGRHkdK7VHl7PBUCE=";
		
		boolean valid = crypto.verifySignature(TestParameters.getECPublicKey1(),
				message, Base64.decodeBase64(signature));
		
		assertTrue(valid);
	}
	
	@Test
	public void verifySignatureException() throws Exception {
		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new Random(0), modulus);
		PublicKey publicKey = null;
		
		List<byte[]> message = new ArrayList<byte[]>();
		message.add("salt".getBytes());
		message.add("M1".getBytes());
		
		String signature = "MEUCIQDgBr+QnM9MsEz7wpvvqwDlBOrmZcEARjgPre61F4"
				+ "NsJAIgQJGz2Pl9Bc5BOg+XQFBQ0rLmufvGRHkdK7VHl7PBUCE=";
		
		boolean valid = crypto.verifySignature(publicKey, message, Base64.decodeBase64(signature));
		assertFalse(valid);
	}
	
	
	@Test
	public void verifyBadSignaure() throws Exception {
		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new Random(0), modulus);

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
		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new Random(0), modulus);

		assertEquals(32, crypto.getBytes(32).length);
		assertEquals(1, crypto.getBytes(1).length);
		assertEquals(256, crypto.getBytes(256).length);
		assertEquals(257, crypto.getBytes(257).length);
	}

	@Test
	public void testGetStandardRSAKey() throws Exception {
		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new Random(0), modulus);
		RSAPublicKey pk = (RSAPublicKey)crypto.getStandardRSAkey();
		
		assertEquals(exponent, pk.getPublicExponent());
		assertEquals(modulus, pk.getModulus());
	}
	
	@Test
	public void testGetModulus() {
		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new Random(0), modulus);
		assertEquals(modulus, crypto.getModulus());

	}

	@Test
	public void testGenerateKeyFromBytes() throws Exception {
		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new Random(0), modulus);
		byte[] seed = "thisIsMySeed".getBytes();
		KeyPair pair1 = crypto.generateKeysFromBytes(seed);
		assertTrue(pair1.getPrivate() instanceof PrivateKey);
		assertTrue(pair1.getPublic() instanceof PublicKey);
	}
	
	@Test
	public void testHash() throws Exception {
		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new Random(0), modulus);
		
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
		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new Random(0), modulus);
		
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
		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new Random(0), modulus);
		BIG rnd = crypto.getRandomNumber();
		assertThat(rnd, IsInstanceOf.instanceOf(BIG.class));
	}

	@Test
	public void testHashAndMultiply() {
		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new Random(0), modulus);
		
		BIG r = BIG.fromBytes(Base64.decodeBase64("HE5cdHpR6FWeCjsAQZApcpH"
				+ "xluW9CEU8wbkseMn6q1McTlx0elHoVZ4KOwBBkClykfGW5b0IRTzBuQ"
				+ "=="));
		
		ECP point = crypto.hashAndMultiply(r, "inputValue".getBytes());
		byte[] bytes = new byte[58*2+1];
		point.toBytes(bytes, false);
		String expected = "BBQ0UhpUSpoVirzk86PKkrs62yDfaDtgRkhfPHXL9cKE+YJy9W+XkdLFecPuA7I68AWStuxHtmKw" +
				"cMsGonBq/ePeJksuRq6nvnSdSFaHtBqZvbXzpdSr6zOdJhgOHUgiuU+N750SOzhew5qW1tIgJmmAEr/C";
		assertEquals(expected, b64(bytes));
	}
	
	private String b64(byte[] input) {
		return Base64.encodeBase64String(input);
	}

}
