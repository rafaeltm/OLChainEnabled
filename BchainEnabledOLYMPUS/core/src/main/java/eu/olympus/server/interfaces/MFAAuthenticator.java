package eu.olympus.server.interfaces;

import java.util.List;

public interface MFAAuthenticator {
	
	public boolean isValid(String token, String secret);

	public String generateTOTP(String secret);

	public String generateSecret();

	public String combineSecrets(List<String> secrets);
}
