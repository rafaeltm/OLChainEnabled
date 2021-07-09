package eu.olympus.unit.util.multisingMock;

import eu.olympus.model.exceptions.MSSetupException;
import eu.olympus.util.Pair;
import eu.olympus.util.multisign.*;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.rangeProof.model.PedersenCommitment;

import java.util.Map;
import java.util.Set;

public class MockMs implements MS {


    @Override
    public MSpublicParam setup(int n, MSauxArg aux, byte[] seed) throws MSSetupException {
        return null;
    }

    @Override
    public Pair<MSprivateKey, MSverfKey> kg() {
        return null;
    }

    @Override
    public MSverfKey kAggreg(MSverfKey[] vks) {
        return null;
    }

    @Override
    public MSsignature sign(MSprivateKey sk, MSmessage m) {
        return null;
    }

    @Override
    public MSsignature comb(MSverfKey[] vks, MSsignature[] signs) {
        return null;
    }

    @Override
    public boolean verf(MSverfKey avk, MSmessage m, MSsignature sign) {
        return false;
    }

    @Override
    public MSzkToken presentZKtoken(MSverfKey avk, Set<String> revealedAttributes, MSmessage attributes, String m, MSsignature sign) {
        return null;
    }

    @Override
    public boolean verifyZKtoken(MSzkToken token, MSverfKey avk, String m, MSmessage revealedAttributes) {
        return false;
    }

    @Override
    public MSzkToken presentZKtokenModified(MSverfKey avk, Set<String> revealedAttributes, Map<String, PedersenCommitment> Vp, MSmessage attributes, String m, MSsignature sign) {
        return null;
    }

    @Override
    public boolean verifyZKtokenModified(MSzkToken token, MSverfKey avk, String m, MSmessage revealedAttributes, Map<String, Group1Element> Vp) {
        return false;
    }
}