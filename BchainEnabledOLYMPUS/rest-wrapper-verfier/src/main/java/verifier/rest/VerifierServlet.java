package verifier.rest;

import eu.olympus.client.PestoIdPRESTConnection;
import eu.olympus.model.Policy;
import eu.olympus.verifier.OLVerificationLibraryPS;
import eu.olympus.verifier.W3CPresentationVerifierOL;
import eu.olympus.verifier.W3CVerificationResult;
import eu.olympus.verifier.interfaces.W3CPresentationVerifier;

import javax.servlet.ServletContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Path("/verifier")
public class VerifierServlet {
    private static final byte[] seed="randomSeedNotNeeded".getBytes(StandardCharsets.UTF_8);
    private static final String bearer="NotNeededBearerToken";

    @Context ServletContext context;

    @Path(VerifierEndpoints.SETUP)
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public void setup(SetupModel request) throws Exception {
        System.out.println("Got a setup request");
        OLVerificationLibraryPS library=new OLVerificationLibraryPS();
        List<PestoIdPRESTConnection> connections = new ArrayList<>();
        for (String s : request.getUrls()) {
            PestoIdPRESTConnection pestoIdPRESTConnection = new PestoIdPRESTConnection(s, bearer, 0);
            connections.add(pestoIdPRESTConnection);
        }
        library.setup(connections,seed);
        W3CPresentationVerifier verifier=new W3CPresentationVerifierOL(library);
        context.setAttribute("verifier",verifier);
    }

    @Path(VerifierEndpoints.VERIFY)
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public boolean verify(VerificationModel request) throws Exception {
        System.out.println("Got a verify request");
        W3CPresentationVerifier verifier= (W3CPresentationVerifier) context.getAttribute("verifier");
        W3CVerificationResult result=verifier.verifyPresentationToken(request.getToken(),request.getPolicy());
        return result == W3CVerificationResult.VALID;
    }

}
