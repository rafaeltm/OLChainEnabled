import verifier.rest.SetupModel;
import verifier.rest.VerificationModel;
import verifier.rest.VerifierEndpoints;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;

public class VerifierRESTConnection {

    private String host;

    private Client client;

    public VerifierRESTConnection(String url) {
        this.host = url+"/verifier/";
        this.client = ClientBuilder.newClient();
    }

    public void setup(SetupModel data){
        client.target(host+ VerifierEndpoints.SETUP).request().post(Entity.entity(data, MediaType.APPLICATION_JSON));
    }

    public boolean verify(VerificationModel data){
        return client.target(host+ VerifierEndpoints.VERIFY).request().post(Entity.entity(data, MediaType.APPLICATION_JSON),Boolean.class);
    }

}
