package com.um.inf.olchain.olympus;

import android.content.Context;
import android.util.Log;
import android.widget.Toast;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.um.inf.olchain.R;
import com.um.inf.olchain.rest.APIService;
import com.um.inf.olchain.rest.APIUtils;
import com.um.inf.olchain.rest.chainmodels.AttributeDefinitionLedger;
import com.um.inf.olchain.rest.chainmodels.PublicParamsLedger;
import com.um.inf.olchain.rest.chainmodels.Vidp;
import com.um.inf.olchain.rest.signapimodels.ChainQuery;
import com.um.inf.olchain.utils.Utils;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import eu.olympus.client.PSCredentialManagement;
import eu.olympus.client.PabcClient;
import eu.olympus.client.PestoIdPRESTConnection;
import eu.olympus.client.SoftwareClientCryptoModule;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.client.interfaces.CredentialStorage;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.model.AttributeDefinitionBoolean;
import eu.olympus.model.AttributeDefinitionDate;
import eu.olympus.model.AttributeDefinitionInteger;
import eu.olympus.model.AttributeDefinitionString;
import eu.olympus.model.PabcPublicParameters;
import eu.olympus.util.Pair;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.util.psmultisign.PSverfKey;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;
import shaded.org.apache.commons.codec.binary.Base64;

//TODO Create configurable local (i.e., number of IdPs, ports, TLS or not, storage...)
public class BasicLocalIdPConfiguration implements ClientConfiguration {

    private APIService apiService = APIUtils.getAPIService();

    private final static String url = "http://10.0.2.2:";
    private static String adminCookie;
    private CredentialStorage storage;
    private static final byte[] seed = "random value random value random value random value random".getBytes();

    private Vidp idp = null;
    private PublicParamsLedger  pubParams = null;

    public BasicLocalIdPConfiguration(CredentialStorage storage) {
        this.storage = storage;
    }

    @Override
    public Pair<UserClient, CredentialManagement> createClient(Context context) throws Exception {
        try {
            Gson gson = new Gson();
            String idpJSON = Utils.secureSharedPreferences(context).getString("vidp", "");
            idp = gson.fromJson(idpJSON, Vidp.class);
            Log.d("BASIC-CONFIG", "IDP: " + idp.getDid().getId() + " ENDPOINTS: " + idp.getDid().getServices().get(0).getEndpoint() + " || " + idp.getDid().getServices().get(1).getEndpoint() + " || " + idp.getDid().getServices().get(2).getEndpoint());
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        Random rnd = new Random(1);
        byte[] rawCookie = new byte[64];
        rnd.nextBytes(rawCookie);
        adminCookie = Base64.encodeBase64String(rawCookie);
        List<PestoIdPRESTConnection> idps = new ArrayList<>();
        int serverCount = 3;
        int port = 9080;

        /**
         * GET THE CONNECTION ENDPOINT FROM THE IDP RECOVERED FROM LEDGER
         */
        if (idp != null) {
            serverCount = idp.getDid().getServices().size();
            for (int i = 0; i < serverCount; i++) {
                PestoIdPRESTConnection rest = new PestoIdPRESTConnection(idp.getDid().getServices().get(i).getEndpoint().contains("http://") ? idp.getDid().getServices().get(i).getEndpoint() : "http://" + idp.getDid().getServices().get(i).getEndpoint(), adminCookie, i);
                Log.d("REST-IDP", rest.toString());
                idps.add(rest);
            }
        } else {
            for (int i = 0; i < serverCount; i++) {
                PestoIdPRESTConnection rest = new PestoIdPRESTConnection(url + (port+i), adminCookie, i);
                idps.add(rest);
            }
        }

        Map<Integer, MSverfKey> publicKeys = new HashMap<>();
        for (Integer j = 0; j < serverCount; j++) {
            MSverfKey pubKeyShare = idps.get(j).getPabcPublicKeyShare();
            if (idp != null) {
                // CHECK PUBLIC KEY SHARE
                boolean res = idp.getDid().getServices().get(j).getPk().equals(Base64.encodeBase64String(pubKeyShare.getEncoded()));
                byte[] pkDecoded = Base64.decodeBase64(idp.getDid().getServices().get(j).getPk());
                publicKeys.put(j, new PSverfKey(pkDecoded));
                Log.d("CHECK PUB-KEY-SHARE", "RES: " + res);
            } else {
                publicKeys.put(j, pubKeyShare);
            }
        }
        this.pubParams = getPublicParamsFromLedger(idp.getDid().getServices().get(0).getId()).body();
        PabcPublicParameters publicParam = idps.get(0).getPabcPublicParam();
        if(this.pubParams.getSchema().getEncodedSchemePublicParam().equals(publicParam.getEncodedSchemePublicParam())) {
            Log.d("COMPARE-PUB-PARAMS", "True");
        } else {
            Log.d("COMPARE-PUB-PARAMS", "False");
            Toast toast = Toast.makeText(context, R.string.warningPubParams, Toast.LENGTH_LONG);
            toast.show();
        }

        CredentialManagement credentialManagement = new PSCredentialManagement(true, storage, 365);
        ((PSCredentialManagement) credentialManagement).setup(publicParam, publicKeys, seed);

        ClientCryptoModule cryptoModule = new SoftwareClientCryptoModule(new Random(1),
                ((RSAPublicKey) idps.get(0).getCertificate().getPublicKey()).getModulus());

        return new Pair<>(new PabcClient(idps, credentialManagement, cryptoModule), credentialManagement);
    }

    private Response<PublicParamsLedger> getPublicParamsFromLedger(String partialIdPId) {
        ChainQuery query = new ChainQuery(partialIdPId, "", "", "", "", "");
        try {
            return apiService.getLedgerSchema(query).execute();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
