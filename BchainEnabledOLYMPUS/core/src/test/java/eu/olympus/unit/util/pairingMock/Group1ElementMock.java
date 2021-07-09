package eu.olympus.unit.util.pairingMock;


import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.ZpElement;

public class Group1ElementMock implements Group1Element {


    @Override
    public Group1Element mul(Group1Element el2) {
        return null;
    }

    @Override
    public Group1Element exp(ZpElement exp) {
        return null;
    }

    @Override
    public Group1Element invExp(ZpElement exp) {
        return null;
    }

    @Override
    public boolean isUnity() {
        return false;
    }

    @Override
    public PabcSerializer.Group1Element toProto() {
        return null;
    }

    @Override
    public Group1Element multiExp(Group1Element[] elements, ZpElement[] exponents) {
        return null;
    }

    @Override
    public byte[] toBytes() {
        return new byte[0];
    }
}
