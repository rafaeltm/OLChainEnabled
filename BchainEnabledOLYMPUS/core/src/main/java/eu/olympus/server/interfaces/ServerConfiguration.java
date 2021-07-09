package eu.olympus.server.interfaces;

import java.security.cert.Certificate;
import java.util.List;

public interface ServerConfiguration {


	public String getKeyStorePath();

	public String getTrustStorePath();

	public String getKeyStorePassword();
	
	public String getTrustStorePassword();

	public int getPort();
	
//	public PESTOConfiguration getPestoConfiguration();
	
	public List<String> getServers();
		
	public int getTlsPort();
	
//	public PABCConfiguration getPabcConfiguration();

	public Certificate getCert();

}
