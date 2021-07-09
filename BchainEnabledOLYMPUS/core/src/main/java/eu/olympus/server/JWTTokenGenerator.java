package eu.olympus.server;


import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.algorithms.Algorithm;
import eu.olympus.model.Attribute;
import eu.olympus.server.interfaces.TokenGenerator;

public class JWTTokenGenerator implements TokenGenerator {

	Algorithm algorithm;
	RSAPrivateKey privateKey;
	RSAPublicKey publicKey;
	
	public JWTTokenGenerator() {
		this.algorithm = null;
	}

	@Override
	public String generateToken(Map<String, Attribute> assertions) throws Exception {
		if(algorithm == null) {
			//Automatically run key generation?
			throw new Exception("Keys not configured");
		}
		Builder b = JWT.create();
		for(String attribute : assertions.keySet()) {
			Object value = ((Attribute)assertions.get(attribute)).getAttr();
			if(value instanceof String) {
				b.withClaim(attribute, (String)value);	
			} else if(value instanceof Integer) {
				b.withClaim(attribute, (Integer)value);
			} else {
				throw new Exception("Assertion type not supported");
			}
			
		}
		return b.sign(algorithm);
	}
	
	public void setKeys(RSAPrivateKey privKey, RSAPublicKey pubKey) throws Exception{
		this.privateKey = privKey;
		this.publicKey = pubKey;
		this.algorithm = Algorithm.RSA256(this.publicKey, this.privateKey);
	}


	@Override
	public PublicKey getPublicKey() {
		return this.publicKey;
	}

}
