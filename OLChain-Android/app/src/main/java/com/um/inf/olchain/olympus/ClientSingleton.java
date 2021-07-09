package com.um.inf.olchain.olympus;

import android.content.Context;

import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.util.Pair;

//TODO Safe reinitialization (if it may be deleted by Android to free memory)?
public class ClientSingleton {
    private static UserClient client;
    private static final String TAG = ClientSingleton.class.getSimpleName();
    private static CredentialManagement credentialManagement;

    public static void initialize(ClientConfiguration config, Context context) throws Exception {
        if (client != null)
            throw new IllegalStateException("Method initialize must be called only once");

        Pair<UserClient, CredentialManagement> res = config.createClient(context);
        client = res.getFirst();
        credentialManagement = res.getSecond();
    }

    public static UserClient getInstance() {
        if (client == null) {
            throw new IllegalStateException("Method initialize must be successfully completed before getting an instance");
        }
        return client;
    }

    public static CredentialManagement getCredentialManager(){
        if (client == null)
            throw new IllegalStateException("Method initialized must be succesfully completed before getting an instance");
        return credentialManagement;
    }

    public static boolean isInitialized() {
        return client != null;
    }
}
