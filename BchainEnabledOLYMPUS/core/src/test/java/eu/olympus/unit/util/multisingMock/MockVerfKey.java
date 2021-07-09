package eu.olympus.unit.util.multisingMock;

import eu.olympus.util.multisign.MSverfKey;

public class MockVerfKey implements MSverfKey {

    @Override
    public String getAlgorithm() {
        return null;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }
}
