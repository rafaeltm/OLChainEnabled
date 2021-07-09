package com.um.inf.olchain.olympus;

import android.content.Context;
import android.util.Log;
import com.um.inf.olchain.utils.Utils;
import java.util.Date;
import VCModel.Verifiable;
import VCModel.VerifiableCredential;
import eu.olympus.client.interfaces.CredentialStorage;

public class EncryptedCredentialStorage implements CredentialStorage {

    private String filename;
    private Context context;

    public EncryptedCredentialStorage(String filename,Context context){
        this.filename=filename;
        this.context=context;
    }


    @Override
    public void storeCredential(VerifiableCredential verifiableCredential) {
        byte[] content = verifiableCredential.toJSONString().getBytes();
        Log.d("EncryptedStorage","Store "+ verifiableCredential.toJSONString());
        Utils.writeEncrypted(filename, content, context);
    }

    @Override
    public VerifiableCredential getVCredential() {
        try {
            byte[] content= Utils.readEncrypted(filename,context);
            Log.d("EncryptedStorage","Get "+ new String(content));
            return new VerifiableCredential(Verifiable.getJSONMap(new String(content)));
        } catch (Exception e) {
            Log.d("EncryptedStorage","Cannot retrieve credential");
        }
        return null;
    }

    @Override
    public boolean checkCredential() {
        try {
            byte[] content = Utils.readEncrypted(filename,context);
            String stringCred = new String(content);
            VerifiableCredential currentCredential = new VerifiableCredential(Verifiable.getJSONMap(stringCred));
            if(currentCredential.getExpirationDate().before(new Date())){
                deleteCredential();
                Log.d("EncryptedStorage","Expired credential");
                return false;
            }
            return true;
        } catch (Exception e) {
            Log.d("EncryptedStorage","No credential");
        }
        return false;
    }

    @Override
    public void deleteCredential() {
        Utils.writeEncrypted(filename,new byte[0],context);
    }
}