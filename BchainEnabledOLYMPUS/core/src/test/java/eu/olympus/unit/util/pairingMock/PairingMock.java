package eu.olympus.unit.util.pairingMock;


import eu.olympus.util.Pair;
import eu.olympus.util.pairingInterfaces.Group2Element;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.Group3Element;
import eu.olympus.util.pairingInterfaces.Pairing;

import java.util.Collection;

public class PairingMock implements Pairing {


    @Override
    public Group3Element pair(Group2Element el1, Group1Element el2) {
        return null;
    }

    @Override
    public Group3Element multiPair(Collection<Pair<Group2Element, Group1Element>> elements) {
        return null;
    }
}
