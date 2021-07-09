package verifier;

import verifier.rest.VerifierServer;

public class RunServer {


    public static void main(String[] args) throws Exception{
        if(args.length!=1) {
            System.out.println("Need port parameter");
            return;
        }
        int port;
        try{
            port = Integer.parseInt(args[0]);
            System.out.println("Running client-server on port: "+port);
        } catch(Exception e) {
            System.out.println("Failed to parse port");
            return;
        }
        VerifierServer server=VerifierServer.getInstance();
        server.start(port,0,null, null,null);
    }
}
