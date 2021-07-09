package com.um.inf.olchain.olympus;

import android.content.Context;

import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.util.Pair;

public interface ClientConfiguration {
    Pair<UserClient, CredentialManagement> createClient(Context context) throws Exception;
}
