package eu.olympus.unit.util.pairingMock;

import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.pairingInterfaces.Group2Element;
import eu.olympus.util.pairingInterfaces.ZpElement;

public class Group2ElementMock implements Group2Element {

    @Override
    public Group2Element mul(Group2Element el2) {
        return null;
    }

    @Override
    public Group2Element exp(ZpElement exp) {
        return null;
    }

    @Override
    public Group2Element invExp(ZpElement exp) {
        return null;
    }

    @Override
    public boolean isUnity() {
        return false;
    }

    @Override
    public PabcSerializer.Group2Element toProto() {
        return null;
    }

    @Override
    public byte[] toBytes() {
        return new byte[0];
    }
}
