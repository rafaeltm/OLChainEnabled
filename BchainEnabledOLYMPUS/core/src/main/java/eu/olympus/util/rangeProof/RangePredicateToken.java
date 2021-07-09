package eu.olympus.util.rangeProof;

import com.google.protobuf.InvalidProtocolBufferException;
import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.pairingBLS461.Group1ElementBLS461;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.rangeProof.model.RangeProof;
import org.apache.commons.codec.binary.Base64;

public class RangePredicateToken {
    private RangeProof proofLowerBound;
    private RangeProof proofUpperBound;
    private Group1Element commitV;

    public RangePredicateToken(RangeProof proofLowerBound, RangeProof proofUpperBound, Group1Element commitV) {
        this.proofLowerBound = proofLowerBound;
        this.proofUpperBound = proofUpperBound;
        this.commitV = commitV;
    }

    public RangePredicateToken(String encodedProofLowerBound, String encodedProofUpperBound, String encodedCommitV) throws InvalidProtocolBufferException {
        if(encodedProofLowerBound==null || encodedProofUpperBound==null || encodedCommitV==null)
            throw new InvalidProtocolBufferException("Null value");
        this.proofLowerBound = new RangeProof(PabcSerializer.RangeProof.parseFrom(Base64.decodeBase64(encodedProofLowerBound)));
        this.proofUpperBound = new RangeProof(PabcSerializer.RangeProof.parseFrom(Base64.decodeBase64(encodedProofUpperBound)));
        this.commitV = new Group1ElementBLS461(PabcSerializer.Group1Element.parseFrom(Base64.decodeBase64(encodedCommitV)));
    }

    public RangePredicateToken(PabcSerializer.RangePredToken rangePredToken) {
        this.proofLowerBound=new RangeProof(rangePredToken.getProofLowerBound());
        this.proofUpperBound=new RangeProof(rangePredToken.getProofUpperBound());
        this.commitV=new Group1ElementBLS461(rangePredToken.getCommitV());
    }

    public RangeProof getProofLowerBound() {
        return proofLowerBound;
    }

    public RangeProof getProofUpperBound() {
        return proofUpperBound;
    }

    public Group1Element getCommitV() {
        return commitV;
    }

    public PabcSerializer.RangePredToken toProto() {
        return PabcSerializer.RangePredToken.newBuilder().setCommitV(commitV.toProto())
                .setProofLowerBound(proofLowerBound.toProto()).setProofUpperBound(proofUpperBound.toProto()).build();
    }

    public String getEncoded() {
        return Base64.encodeBase64String(toProto().toByteArray());
    }

    public String getEncodedCommitV() {
        return Base64.encodeBase64String(this.commitV.toProto().toByteArray());
    }
}
