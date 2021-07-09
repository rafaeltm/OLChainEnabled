package eu.olympus.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import eu.olympus.util.Util;
import eu.olympus.util.pairingBLS461.PairingBLS461;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class AttributeDefinitionString extends AttributeDefinition {

    @JsonProperty("type") //Needed because of issue in Jackson with serialization of collections
    private final String type= "String";
    private final AttributeType TYPE= AttributeType.STRING;
    private final int minLength;
    private final int maxLength;
    private static final BigInteger mod=Util.BIGToBigInteger(PairingBLS461.p);

    public AttributeDefinitionString(@JsonProperty("id") String id, @JsonProperty("shortName") String shortName,@JsonProperty("minLength") int minLength,@JsonProperty("maxLength") int maxLength) {
        super(id, shortName);
        this.minLength = minLength;
        this.maxLength = maxLength;
    }

    public int getMinLength() {
        return minLength;
    }

    public int getMaxLength() {
        return maxLength;
    }

    @Override
    public BigInteger toBigIntegerRepresentation(Attribute attribute) {
        if(!checkValidValue(attribute))
            throw new IllegalArgumentException("Invalid attribute");
        String input= (String) attribute.getAttr();
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-512");
            digest.reset();
            digest.update(input.getBytes("utf8"));
            BigInteger hashResult=new BigInteger(1, digest.digest());
            return  hashResult.mod(mod);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            throw new RuntimeException("Could not setup SHA512");
        }
    }


    @Override
    public boolean checkValidValue(Attribute value) {
        if(value.getType()!=TYPE || !(value.getAttr() instanceof String))
            return false;
        int valueLength= ((String) value.getAttr()).length();
        return valueLength>=minLength && valueLength<=maxLength;
    }
}
