package eu.olympus.client;

import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.CredentialManagement;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.client.rest.RESTUserClient;

public class RunPestoClientServer {

	public static void main(String[] args) throws Exception{
		if(args.length<3) {
			System.out.println("Minimum parameters are type, port and a list of hosts, ie. execute \"main pesto 999 http://localhost:8080 http://localhost:8081\" to run a pesto server on port 999");
			System.out.println("and use pIdP servers running on localhost port 8080 and 8081");
			System.out.println("Valid client types are: 'pesto' and 'pabc'");
			return;
		}
		int portClient = 9070;
		try{
			portClient = Integer.parseInt(args[1]);
			System.out.println("Running client-server on port: "+portClient);
		} catch(Exception e) {
			System.out.println("Failed to parse port");
			return;
		}
		
		
		List<PestoIdPRESTConnection> idps = new ArrayList<PestoIdPRESTConnection>();	
		System.out.println("vIdP consists of: ");
		for(int i = 2; i< args.length; i++) {
			System.out.println("Server "+(i-1)+": "+args[i]);
			PestoIdPRESTConnection idp = new PestoIdPRESTConnection(args[i], "", i-1); //We don't support admin/server role or MFA
			idps.add(idp);
		}
		try{
			ClientCryptoModule crypto = new SoftwareClientCryptoModule(new SecureRandom(), ((RSAPublicKey)idps.get(0).getCertificate()).getModulus());
			
			UserClient client = null;
			if("pabc".equals(args[0])) {
					CredentialManagement credentialManagement = new PSCredentialManagement(false,null, 60);
				client = new PabcClient(idps, credentialManagement, crypto);
			} else if ("pesto".equals(args[0])) {
				client = new PestoClient(idps, crypto);			
			} else {
				System.out.println(args[0] +" is not a valid client type. It must be either \"pesto\" or \"pabc\".");
				System.exit(0);
			}


			RESTUserClient restClient = new RESTUserClient();
		
			restClient.setClient(client);
			restClient.start(portClient, 0, null, null, null);
		} catch(Exception e){
			e.printStackTrace();
			System.out.println("Failed to start client");
			System.exit(0);
		}
	}
}
