package eu.olympus.client;

import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.Attribute;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.IdentityProof;
import eu.olympus.model.server.rest.UsernameAndPassword;
import eu.olympus.server.PasswordJWTIdP;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;

public class PasswordJWTClient implements UserClient {

	private final Map<Integer, PasswordJWTIdP> servers;
	protected Map<Integer, byte[]> sessionCookies;
	protected Map<Integer, Long> sessionStartedTimes;
	public static final long sessionLength = 6000000;
	public String password = null;

	public PasswordJWTClient(List<PasswordJWTIdP> servers) {
		this.servers = new HashMap<>();
		this.sessionCookies = new HashMap<>();
		this.sessionStartedTimes = new HashMap<>();
		int i = 0;
		for(PasswordJWTIdP server:servers){
			this.servers.put(i,server);
			sessionStartedTimes.put(i, 0l);
			i++;
		}
	}

	@Override
	public void createUser(String username, String password) throws UserCreationFailedException {
		servers.get(0).createUser(new UsernameAndPassword(username, password));
	}

	@Override
	public void createUserAndAddAttributes(String username, String password, IdentityProof identityProof) throws UserCreationFailedException {
		servers.get(0).createUserAndAddAttributes(new UsernameAndPassword(username, password), identityProof);
	}

	@Override
	public void addAttributes(String username, String password,
			IdentityProof identityProof, String token, String type) throws AuthenticationFailedException {
		try {
			ensureActiveSession(username, password, token, type);
			servers.get(0).addAttributes(username, sessionCookies.get(0), identityProof);
		} catch(Exception e) {
			throw new AuthenticationFailedException(e);
		}
	}

	@Override
	public String authenticate(String username, String password, Policy policy, String token, String type) throws AuthenticationFailedException {
		ensureActiveSession(username, password, token, type);
		String reply = servers.get(0).authenticate(username, sessionCookies.get(0), policy);
		if(reply == null) {
			throw new AuthenticationFailedException("Failed to authenticate");
		}
		return reply;
	}

	@Override
	public Map<String, Attribute> getAllAttributes(String username, String password, String token, String type) throws AuthenticationFailedException {
		try {
			ensureActiveSession(username, password, token, type);
			return servers.get(0).getAllAttributes(username, sessionCookies.get(0));
		}catch(Exception e) {
			throw new AuthenticationFailedException(e);
		}
	}

	@Override
	public void deleteAttributes(String username, String password, List<String> attributes, String token, String type) throws AuthenticationFailedException{
		try {
			ensureActiveSession(username, password, token, type);
			if(!servers.get(0).deleteAttribute(username, sessionCookies.get(0), attributes)) {
				throw new AuthenticationFailedException("Authentication failed");
			}
		}catch(Exception e) {
			throw new AuthenticationFailedException(e);
		}
	}

	@Override
	public void deleteAccount(String username, String password, String token, String type) throws AuthenticationFailedException {
		try{
			ensureActiveSession(username, password, token, type);

			if (!servers.get(0).deleteAccount(new UsernameAndPassword(username, password), sessionCookies.get(0))) {
				throw new AuthenticationFailedException("Authentication failed");
			}
		}catch(Exception e) {
			throw new AuthenticationFailedException(e);
		}
	}

	@Override
	public void changePassword(String username, String oldPassword, String newPassword, String token, String type) throws UserCreationFailedException, AuthenticationFailedException{
		try {
			ensureActiveSession(username, oldPassword, token, type);
			servers.get(0).changePassword(new UsernameAndPassword(username, oldPassword), newPassword,
					sessionCookies.get(0));
		}catch(Exception e) {
			throw new AuthenticationFailedException(e);
		}
	}

	@Override
	public String requestMFAChallenge(String username, String password, String type)
			throws AuthenticationFailedException {
		ensureActiveSession(username, password, null, "NO_MFA");
		return servers.get(0)
				.requestMFA(new UsernameAndPassword(username, password), sessionCookies.get(0), type);
	}

	@Override
	public void confirmMFA(String username, String password, String token, String type)
			throws AuthenticationFailedException {
		ensureActiveSession(username, password, null, "NO_MFA");
		if (!servers.get(0)
				.confirmMFA(new UsernameAndPassword(username, password), sessionCookies.get(0), token,
						type)) {
			throw new AuthenticationFailedException("Could not confirm MFA");
		}
	}

	@Override
	public void removeMFA(String username, String password, String token, String type)
			throws AuthenticationFailedException {
		ensureActiveSession(username, password, token, type);
		if (!servers.get(0)
				.removeMFA(new UsernameAndPassword(username, password), sessionCookies.get(0), token,
						type)) {
			throw new AuthenticationFailedException("Could not remove MFA");
		}
	}

	@Override
	public void clearSession() {
		this.sessionCookies.clear();
		this.sessionStartedTimes.clear();
		for(int i=0; i< servers.size(); i++){
			sessionStartedTimes.put(i, 0l);
		}
	}
	
	private void ensureActiveSession(String username, String password, String token, String type) throws AuthenticationFailedException {
		if (System.currentTimeMillis() >= (sessionStartedTimes.get(0) + sessionLength)) {
			String sessionCookie = servers.get(0)
					.startSession(new UsernameAndPassword(username, password), token, type);
			sessionCookies.put(0, Base64.decodeBase64(sessionCookie));
		}
		// Renew current session
		sessionStartedTimes.put(0, System.currentTimeMillis());
	}
}
