package eu.olympus.unit.util.pairingMock;


import eu.olympus.util.pairingInterfaces.Group3Element;
import eu.olympus.util.pairingInterfaces.ZpElement;

public class Group3ElementMock implements Group3Element {
    @Override
    public Group3Element mul(Group3Element el2) {
        return null;
    }

    @Override
    public Group3Element exp(ZpElement exp) {
        return null;
    }

    @Override
    public Group3Element invExp(ZpElement exp) {
        return null;
    }

    @Override
    public boolean isUnity() {
        return false;
    }
}

