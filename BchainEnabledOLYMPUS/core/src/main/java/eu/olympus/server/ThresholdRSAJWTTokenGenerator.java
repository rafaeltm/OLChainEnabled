package eu.olympus.server;

import java.nio.charset.Charset;
import java.security.PublicKey;
import java.util.Map;

import eu.olympus.model.Attribute;

import org.apache.commons.codec.Charsets;
import org.apache.commons.codec.binary.Base64;
import org.json.JSONObject;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.interfaces.TokenGenerator;

public class ThresholdRSAJWTTokenGenerator implements TokenGenerator {

	private ServerCryptoModule cryptoModule;

	public static byte JWT_PART_SEPARATOR = (byte)46;
	
	public ThresholdRSAJWTTokenGenerator(ServerCryptoModule cModule) {
		this.cryptoModule = cModule;
	}

	@Override
	public String generateToken(Map<String, Attribute> assertions) throws Exception {

		String header = buildJWTHeader();
		byte[] headerBytes = header.getBytes(Charset.defaultCharset());//Should be UTF-8
		String payload = buildJWTPayload(assertions);
		byte[] payloadBytes = payload.getBytes(Charset.defaultCharset());
		byte[] toBeSigned = new byte[headerBytes.length+payloadBytes.length+1];
		System.arraycopy(headerBytes, 0, toBeSigned, 0, headerBytes.length);
		toBeSigned[headerBytes.length] = JWT_PART_SEPARATOR;
		System.arraycopy(payloadBytes, 0, toBeSigned, headerBytes.length+1, payloadBytes.length);

		byte[] signature = cryptoModule.sign(toBeSigned);

		String jwtToken = header.concat(".").concat(payload).concat(".").concat(Base64.encodeBase64URLSafeString(signature));
		
		return jwtToken;
	}

	private String buildJWTPayload(Map<String, Attribute> assertions) throws Exception{
		JSONObject json = new JSONObject(assertions);
		return Base64.encodeBase64URLSafeString(json.toString().getBytes(Charsets.UTF_8));
	}

	private String buildJWTHeader() {
		JSONObject json = new JSONObject();
		json.put("alg", "RS256");
		json.put("typ", "JWT");
		return Base64.encodeBase64URLSafeString(json.toString().getBytes(Charsets.UTF_8));
	}

	@Override
	public PublicKey getPublicKey() {
		try {
			return cryptoModule.getStandardRSAkey();
		} catch (Exception e) {
		}
		return null;
	}

}
