package eu.olympus.unit.util.pairingMock;


import eu.olympus.util.Pair;
import eu.olympus.util.pairingInterfaces.Group2Element;
import eu.olympus.util.pairingInterfaces.Hash0;
import eu.olympus.util.pairingInterfaces.ZpElement;

import java.util.List;

public class Hash0Mock implements Hash0 {

    @Override
    public Pair<ZpElement, Group2Element> hash(List<ZpElement> m) {
        return null;
    }
}
