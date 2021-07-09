package eu.olympus.unit.util.pairingMock;


import eu.olympus.util.pairingInterfaces.Group2Element;
import eu.olympus.util.pairingInterfaces.Group3Element;
import eu.olympus.util.pairingInterfaces.Hash2;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.psmultisign.*;

public class Hash2Mock implements Hash2 {


    @Override
    public ZpElement hash(String m, PSverfKey avk, Group2Element sigma1, Group2Element sigma2, Group3Element prodT) {
        return null;
    }
}
