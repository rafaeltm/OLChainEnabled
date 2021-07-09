package eu.olympus.unit.util.pairingMock;


import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.util.pairingInterfaces.*;

public class PairingBuilderMock implements PairingBuilder {


    @Override
    public Pairing getPairing() {
        return new PairingMock();
    }

    @Override
    public void seedRandom(byte[] seed) {

    }

    @Override
    public Group2Element getGroup2Generator() {
        return new Group2ElementMock();
    }

    @Override
    public Group1Element getGroup1Generator() {
        return new Group1ElementMock();

    }

    @Override
    public Group3Element getGroup3Generator() {
        return new Group3ElementMock();
    }

    @Override
    public ZpElement getRandomZpElement() {
        return new ZpElementMock();
    }

    @Override
    public ZpElement getZpElementFromAttribute(Attribute attributeValue, AttributeDefinition attributeDefinition) {
        return null;
    }

    @Override
    public ZpElement getZpElementFromEpoch(long epoch) {
        return new ZpElementMock();
    }

    @Override
    public Hash0 getHash0() {
        return new Hash0Mock();
    }

    @Override
    public Hash1 getHash1() {
        return new Hash1Mock();
    }

    @Override
    public Hash2 getHash2() {
        return new Hash2Mock();
    }

    @Override
    public ZpElement getZpElementZero() {
        return null;
    }

    @Override
    public ZpElement hashZpElementFromBytes(byte[] bytes) {
        return null;
    }

    @Override
    public Group2Element hashGroup2ElementFromBytes(byte[] bytes) {
        return null;
    }

    @Override
    public Group1Element hashGroup1ElementFromBytes(byte[] bytes) {
        return null;
    }

    @Override
    public ZpElement getZpElementOne() {
        return null;
    }

    @Override
    public Hash2Modified getHash2Mod() {
        return null;
    }
}
