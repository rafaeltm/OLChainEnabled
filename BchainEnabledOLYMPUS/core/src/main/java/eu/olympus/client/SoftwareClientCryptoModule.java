package eu.olympus.client;

import eu.olympus.util.CommonCrypto;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.util.ECKeyGenerator;

import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.BLS;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.ROM;
import org.apache.commons.codec.Charsets;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.miracl.core.HASH512;
import org.miracl.core.RAND;

/**
 * Software implementation of the ClientCryptoModule used by PESTO. 
 *
 */
public class SoftwareClientCryptoModule implements ClientCryptoModule{

	private final BigInteger modulus;
	private Random rand;
	private RAND rng = new RAND();
	
	/**
	 * Consructor for the crypto module.
	 * @param random A RNG
	 * @param modulus The modulus of the RSA prime used for the RSA
	 * (vIdP) signing algorithm
	 */
	public SoftwareClientCryptoModule(Random random, BigInteger modulus) {
		Security.addProvider(new BouncyCastleProvider());
		this.rand = random;
		byte[] seed = new byte[CommonCrypto.COMPUTATION_SEC_BYTES];
		rand.nextBytes(seed);
		rng.seed(CommonCrypto.COMPUTATION_SEC_BYTES, seed);
		this.modulus = modulus;
	}

	@Override
	public byte[] sign(PrivateKey privateKey, List<byte[]> message) throws Exception{
		Signature sig = Signature.getInstance("SHA256withECDSA");
		sig.initSign(privateKey);
		for(byte[] bytes : message) {
			sig.update(bytes);
		}
		return sig.sign();
	}	
	
	@Override
	public boolean verifySignature(PublicKey publicKey, List<byte[]> input, byte[] signature) {
		try {
			Signature sig = null;
			if("RSA".equals(publicKey.getAlgorithm())) {
				sig = Signature.getInstance("SHA256withRSA");
			} else {
				sig = Signature.getInstance("SHA256withECDSA");
			}
			sig.initVerify(publicKey);
			for(byte[] bytes: input) {
				sig.update(bytes);
			}
			return sig.verify(signature);
		} catch(Exception e) {
		}
		return false;
	}


	@Override
	public byte[] getBytes(int noOfBytes) {
		byte[] bytes = new byte[noOfBytes];
		rand.nextBytes(bytes);
		return bytes;
	}
	
	@Override
	public PublicKey getStandardRSAkey() throws Exception{
		RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, PUBLIC_EXPONENT);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		return factory.generatePublic(spec);
	}

	@Override
	public BigInteger getModulus() {
		return this.modulus;
	}
	
	@Override
	public KeyPair generateKeysFromBytes(byte[] bytes) throws Exception {
		return ECKeyGenerator.generateKey(bytes);
	}

	@Override
	public byte[] hash(List<byte[]> input) {
		HASH512 h = new HASH512();
		for(byte[] b: input) {
			h.process_array(b);
		}
		return h.hash();
	}

	@Override
	public byte[] constructNonce(String username, long salt) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(salt);
		List<byte[]> toHash = new ArrayList<>();
		toHash.add(buffer.array());
		toHash.add(username.getBytes(Charsets.UTF_8));
		return hash(toHash);
	}

	@Override
	public BIG getRandomNumber() {
		return BIG.random(rng);
	}

	@Override
	public ECP hashAndMultiply(BIG r, byte[] password) {
		BIG order = new BIG(ROM.CURVE_Order);
		r.mod(order);
		return hashToGroup1Element(password).mul(r);
	}

	@Override
	public ECP hashToGroup1Element(byte[] input) {
		return BLS.bls_hash_to_point(input);
	}

}
