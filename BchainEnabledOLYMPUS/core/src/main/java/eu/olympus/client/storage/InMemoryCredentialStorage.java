package eu.olympus.client.storage;

import VCModel.VerifiableCredential;
import eu.olympus.client.interfaces.CredentialStorage;
import eu.olympus.model.PSCredential;

public class InMemoryCredentialStorage implements CredentialStorage {

    public static final int VCTYPE = 1;
    public static final int PSCRED = 0;

    private PSCredential currentCredential;
    private VerifiableCredential currentVCredential;


    @Override
    public void storeCredential(VerifiableCredential credential) {
        currentVCredential = credential;
        currentCredential = null;
    }


    @Override
    public VerifiableCredential getVCredential() {
        return currentVCredential;
    }

    @Override
    public boolean checkCredential() {
        if (currentVCredential == null)
            return false;
        if (currentVCredential.getExpirationDate().getTime() < System.currentTimeMillis()) {
            deleteCredential();
            return false;
        }
        return true;
    }

    @Override
    public void deleteCredential() {
        currentVCredential = null;
    }
}
