package eu.olympus.unit.util.multisingMock;


import eu.olympus.util.multisign.MSauxArg;
import eu.olympus.util.multisign.MSpublicParam;

/**
 * Implementation of the public parameters for PS signatures.
 */
public class MockPublicParam implements MSpublicParam {

    @Override
    public int getN() {
        return 0;
    }

    @Override
    public MSauxArg getAuxArg() {
        return null;
    }

    @Override
    public String getEncoded() {
        return "";
    }
}
