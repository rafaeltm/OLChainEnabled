package eu.olympus.client;

import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.Attribute;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.IdentityProof;
import eu.olympus.model.server.rest.UsernameAndPassword;
import eu.olympus.server.DistributedRSAIdP;
import eu.olympus.util.JWTUtil;
import eu.olympus.util.Util;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;

public class DistributedRSAClient implements UserClient {

	private final Map<Integer, DistributedRSAIdP> servers;
	private final BigInteger modulus;
	protected Map<Integer, byte[]> sessionCookies;
	protected Map<Integer, Long> sessionStartedTimes;
	public static final long sessionLength = 6000000;

	public DistributedRSAClient(List<DistributedRSAIdP> servers) {
		RSAPublicKey pk = (RSAPublicKey)servers.get(0).getCertificate().getPublicKey();
		modulus = pk.getModulus();
		this.sessionCookies = new HashMap<>();
		this.sessionStartedTimes = new HashMap<>();
		int i = 0;
		this.servers = new HashMap<>();
		for(DistributedRSAIdP server : servers){
			this.servers.put(i,server);
			sessionStartedTimes.put(i, 0l);
			i++;
		}
	}

	@Override
	public void createUser(String username, String password) throws UserCreationFailedException {
		for (DistributedRSAIdP server: servers.values()){
			server.createUser(new UsernameAndPassword(username, password));
		}
	}

	@Override
	public void createUserAndAddAttributes(String username, String password, IdentityProof identityProof) throws UserCreationFailedException {
		for (DistributedRSAIdP server: servers.values()){
			server.createUserAndAddAttributes(new UsernameAndPassword(username, password), identityProof);
		}
	}

	@Override
	public void addAttributes(String username, String password,
			IdentityProof identityProof, String token, String type) throws AuthenticationFailedException {
		try {
			ensureActiveSession(username, password, token, type);
			for (DistributedRSAIdP server: servers.values()){
				server.addAttributes(username, sessionCookies.get(server.getId()), identityProof);
			}
		} catch(Exception e) {
			throw new AuthenticationFailedException(e);
		}
	}

	@Override
	public String authenticate(String username, String password, Policy policy, String token, String type) throws AuthenticationFailedException {
		try {
			ensureActiveSession(username, password, token, type);
			List<String> partialTokens = new LinkedList<String>();
			for (DistributedRSAIdP server: servers.values()){
				String partialToken = server.authenticate(username, sessionCookies.get(server.getId()), policy);
				partialTokens.add(partialToken);
			}

			String combinedToken = JWTUtil.combineTokens(partialTokens, modulus);
			return combinedToken;
		} catch(Exception e) {
			throw new AuthenticationFailedException(e);
		}
	}

	@Override
	public Map<String, Attribute> getAllAttributes(String username, String password, String token, String type) throws AuthenticationFailedException {
		try {
			ensureActiveSession(username, password, token, type);
			List<Map<String, Attribute>> maps = new ArrayList<Map<String, Attribute>>(servers.size());
			for (DistributedRSAIdP server: servers.values()){
				maps.add(server.getAllAttributes(username, sessionCookies.get(server.getId())));
			}
			if(Util.verifyIdenticalMaps(maps)) {
				return maps.get(0);
			}
		}catch(Exception e ) {
			throw new AuthenticationFailedException(e);
		}

		throw new AuthenticationFailedException("Differing output from vIdP");
		
	}

	@Override
	public void deleteAttributes(String username, String password, List<String> attributes, String token, String type) throws AuthenticationFailedException {
		try {
			ensureActiveSession(username, password, token, type);
			for (DistributedRSAIdP server: servers.values()){
				if(!server.deleteAttribute(username, sessionCookies.get(server.getId()), attributes)) {
					throw new AuthenticationFailedException("Authentication failed");
				}
			}
		}catch(Exception e ) {
			throw new AuthenticationFailedException(e);
		}
	}

	@Override
	public void deleteAccount(String username, String password, String token, String type) throws AuthenticationFailedException {
		try{
			ensureActiveSession(username, password, token, type);
			for (DistributedRSAIdP server: servers.values()){
				if(! server.deleteAccount(new UsernameAndPassword(username, password), sessionCookies.get(server.getId())) ) {
					throw new AuthenticationFailedException("Authentication failed");
				}
			}
		}catch(Exception e ) {
			throw new AuthenticationFailedException(e);
		}
	}

	@Override
	public void changePassword(String username, String oldPassword, String newPassword, String token, String type) throws UserCreationFailedException, AuthenticationFailedException {
		try {
			ensureActiveSession(username, oldPassword, token, type);
			for (DistributedRSAIdP server : servers.values()) {
				server.changePassword(new UsernameAndPassword(username, oldPassword), newPassword,
						sessionCookies.get(server.getId()));
			}
		}catch(Exception e ) {
			throw new AuthenticationFailedException(e);
		}
	}

	@Override
	public String requestMFAChallenge(String username, String password, String type)
			throws AuthenticationFailedException {
		ensureActiveSession(username, password, null, "NO_MFA");
		List<String> partialChallenges = new LinkedList<String>();
		for (DistributedRSAIdP server : servers.values()) {
			String currentChallenge = server.requestMFA(new UsernameAndPassword(username, password),
					sessionCookies.get(server.getId()), type);
			partialChallenges.add(currentChallenge);
		}
		// Check that all challenges are equal
		if (!partialChallenges.stream().allMatch(c -> c.equals(partialChallenges.get(0)))) {
			throw new AuthenticationFailedException(
					"The authenticators of all the servers are not supplying the same secret");
		}
		return partialChallenges.get(0);
	}

	@Override
	public void confirmMFA(String username, String password, String token, String type)
			throws AuthenticationFailedException {
		ensureActiveSession(username, password, null, "NO_MFA");
		for (DistributedRSAIdP server : servers.values()) {
			if (!server.confirmMFA(new UsernameAndPassword(username, password),
					sessionCookies.get(server.getId()), token, type)) {
				throw new AuthenticationFailedException("Could not confirm MFA");
			}
		}
	}

	@Override
	public void removeMFA(String username, String password, String token, String type)
			throws AuthenticationFailedException {
		ensureActiveSession(username, password, token, type);
		for (DistributedRSAIdP server : servers.values()) {
			if (!server.removeMFA(new UsernameAndPassword(username, password),
					sessionCookies.get(server.getId()), token, type)) {
				throw new AuthenticationFailedException("Could not remove MFA");
			}
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
		for (DistributedRSAIdP server: servers.values()) {
			if (System.currentTimeMillis() >= (sessionStartedTimes.get(server.getId()) + sessionLength)) {
				String sessionCookie = servers.get(server.getId())
						.startSession(new UsernameAndPassword(username, password), token, type);
				sessionCookies.put(server.getId(), Base64.decodeBase64(sessionCookie));
			}
			sessionStartedTimes.put(server.getId(), System.currentTimeMillis());
		}
	}
}
