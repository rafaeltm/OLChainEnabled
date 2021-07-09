package eu.olympus.unit.util.pairingMock;


import eu.olympus.util.pairingInterfaces.Hash1;
import eu.olympus.util.psmultisign.PSverfKey;
import eu.olympus.util.pairingInterfaces.ZpElement;

public class Hash1Mock implements Hash1 {


    @Override
    public ZpElement[] hash(PSverfKey[] vks) {
        return new ZpElement[0];
    }
}
