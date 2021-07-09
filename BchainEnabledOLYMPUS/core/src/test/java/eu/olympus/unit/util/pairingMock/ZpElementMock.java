package eu.olympus.unit.util.pairingMock;


import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.pairingInterfaces.ZpElement;

public class ZpElementMock implements ZpElement {

    @Override
    public ZpElement add(ZpElement el2) {
        return null;
    }

    @Override
    public ZpElement mul(ZpElement el2) {
        return null;
    }

    @Override
    public ZpElement sub(ZpElement el2) {
        return null;
    }

    @Override
    public ZpElement neg() {
        return null;
    }

    @Override
    public ZpElement inverse() {
        return null;
    }

    @Override
    public boolean isUnity() {
        return false;
    }

    @Override
    public ZpElement getBit(int i) {
        return null;
    }

    @Override
    public PabcSerializer.ZpElement toProto() {
        return null;
    }

    @Override
    public byte[] toBytes() {
        return new byte[0];
    }

    @Override
    public int getNBits() {
        return 0;
    }

    @Override
    public ZpElement pow(int i) {
        return null;
    }
}
