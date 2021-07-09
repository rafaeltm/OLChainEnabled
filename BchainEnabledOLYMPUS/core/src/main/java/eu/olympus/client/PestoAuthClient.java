package eu.olympus.client;

import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.Attribute;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.IdentityProof;
import eu.olympus.server.interfaces.PestoIdP;
import eu.olympus.server.rest.CommonRESTEndpoints;
import eu.olympus.server.rest.PestoRESTEndpoints;
import eu.olympus.util.KeySerializer;
import eu.olympus.util.Util;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.apache.commons.codec.Charsets;
import org.apache.commons.codec.binary.Base64;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.CONFIG_BIG;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.FP12;
import org.miracl.core.BLS12461.ROM;

public abstract class PestoAuthClient implements UserClient {

	protected ClientCryptoModule cryptoModule;
	protected Map<Integer, PestoIdP> servers;
	protected ExecutorService executorService;
	protected Map<Integer, byte[]> cookies;
	protected Map<Integer, Long> sessionStartedTimes;
	protected long lastUsedSalt;
	public static final long sessionLength = 6000000;
	private static final String NO_MFA = "NONE";
	private KeyPair signingKeys = null;

	
	public PestoAuthClient(List<? extends PestoIdP> servers, ClientCryptoModule cryptoModule) {
		this.servers = new HashMap<>();
		this.cookies = new HashMap<>();
		this.sessionStartedTimes = new HashMap<>();
		this.cryptoModule = cryptoModule;
		Integer i = 0;
		for(PestoIdP server:servers){
			this.servers.put(i,server);
			sessionStartedTimes.put(i, 0l);
			i++;
		}
		this.executorService= Executors.newFixedThreadPool(servers.size());
		
	}

	protected long getFreshSalt() {
		long currentTime = System.currentTimeMillis();
		if (currentTime <= lastUsedSalt) {
			try {
				Thread.sleep(1 + lastUsedSalt - currentTime);
				lastUsedSalt = System.currentTimeMillis();
			} catch (InterruptedException e) {
				// In case there is a thread interruption just try again
				return getFreshSalt();
			}
		} else {
			lastUsedSalt = currentTime;
		}
		return lastUsedSalt;
	}
	
	@Override
	public void createUser(String username, String password) throws UserCreationFailedException {
		createUserAndAddAttributes(username, password, null);
	}
	
	@Override
	public void addAttributes(String username, String password,
			IdentityProof identityProof, String token, String type) throws AuthenticationFailedException {
		try {
			ensureActiveSession(username, password, token, type);
			long salt = getFreshSalt();
			List<Future<Boolean>> authentications = new ArrayList<Future<Boolean>>();
			byte[][] signature = getSignedNonceAndUid(username, salt, CommonRESTEndpoints.ADD_ATTRIBUTES+identityProof.getStringRepresentation());
			for (PestoIdP server : servers.values()) {
				authentications.add(executorService.submit(() -> server
						.addAttributes(username, cookies.get(server.getId()), salt, signature[server.getId()],
								identityProof.getStringRepresentation())));
			}
			for (Future<Boolean> future : authentications) {
				if (!future.get()) {
					throw new AuthenticationFailedException("Server failed to prove identity");
				}
			}
			updateCurrentSessionTimes();
		} catch (Exception e) {
			// Reset key in case something goes wrong
			signingKeys = null;
			throw new AuthenticationFailedException(e);
		}
	}
	
	@Override
	public void createUserAndAddAttributes(String username, String password, IdentityProof identityProof) throws UserCreationFailedException {
		try{
			final String idProof = identityProof != null ? identityProof.getStringRepresentation() : "";
			ensureActiveSession(username, password, null, NO_MFA);
			long salt = getFreshSalt();
			byte[][] signatures = getSignedNonceAndUid(username, salt, CommonRESTEndpoints.CREATE_USER_AND_ADD_ATTRIBUTES+idProof);
			int approvedCount = 0;
			List<Future<byte[]>> futures = new ArrayList<Future<byte[]>>();
			for (PestoIdP server: servers.values()){
				futures.add(executorService.submit(() -> server.finishRegistration(username, cookies.get(server.getId()), signingKeys.getPublic(), signatures[server.getId()], salt, idProof)));
			}
			byte[][] responseSignatures = new byte[servers.size()][];
			int it = 0;
			for(Future<byte[]> bytes : futures) {
				responseSignatures[it] = bytes.get();
				it++;
			}
			for (int i = 0; i< servers.size(); i++){
				//Verify combined signature
				PublicKey combKey = cryptoModule.getStandardRSAkey();
				List<byte[]> input = new ArrayList<byte[]>();
				input.add(KeySerializer.serialize(signingKeys.getPublic()).getBytes());
				if(cryptoModule.verifySignature(combKey, input, responseSignatures[i])) {
					approvedCount++;
				}
			}
			if(approvedCount != servers.size()) {
				throw new UserCreationFailedException("Not all servers finished registration");
			}
		} catch(Exception e) {
			signingKeys = null;
			throw new UserCreationFailedException(e);
		}
	}

	@Override
	public Map<String, Attribute> getAllAttributes(String username, String password, String token, String type) throws AuthenticationFailedException {
		try{
			ensureActiveSession(username, password, token, type);
			long salt = getFreshSalt();
			byte[][] signature = getSignedNonceAndUid(username, salt, CommonRESTEndpoints.GET_ALL_ATTRIBUTES);

			List<Future<Map<String, Attribute>>> authentications = new ArrayList<Future<Map<String, Attribute>>>();

			for (PestoIdP server: servers.values()){
				authentications.add(executorService.submit(() -> server.getAllAttributes(username, cookies.get(server.getId()), salt, signature[server.getId()])));
			}
			List<Map<String, Attribute>> maps = new ArrayList<>();
			for(Future<Map<String, Attribute>> future : authentications) {
				maps.add(future.get());
			}
			if(!Util.verifyIdenticalMaps(maps)) {
				throw new AuthenticationFailedException("Differing output from vIdP");
			}
			updateCurrentSessionTimes();
			return maps.get(0);
		} catch(Exception e) {
			signingKeys = null;
			throw new AuthenticationFailedException(e);
		}
	}	
	
	@Override
	public void deleteAttributes(String username, String password, List<String> attributes, String token, String type) throws AuthenticationFailedException{
		try{
			ensureActiveSession(username, password, token, type);
			long salt = getFreshSalt();
			byte[][] signature = getSignedNonceAndUid(username, salt, CommonRESTEndpoints.DELETE_ATTRIBUTES);

			List<Future<Boolean>> authentications = new ArrayList<Future<Boolean>>();

			for (PestoIdP server: servers.values()){
				authentications.add(executorService.submit(() -> server.deleteAttributes(username, cookies.get(server.getId()), salt, signature[server.getId()], attributes)));
			}
			for(Future<Boolean> future : authentications) {
				if(!future.get()) {
					throw new AuthenticationFailedException("Server failed to delete attribute");
				}
			}
			updateCurrentSessionTimes();
		} catch(Exception e) {
			signingKeys = null;
			throw new AuthenticationFailedException(e);
		}
	}
	
	/**
	 * Deletes the users account on the vIdP
	 * @param username The username of the user
	 * @param password The users password
	 * @throws AuthenticationFailedException 
	 */
	@Override
	public void deleteAccount(String username, String password, String token, String type) throws AuthenticationFailedException {
		try{
			ensureActiveSession(username, password, token, type);
			long salt = getFreshSalt();
			byte[][] signature = getSignedNonceAndUid(username, salt, PestoRESTEndpoints.DELETE_ACCOUNT);

			List<Future<Boolean>> authentications = new ArrayList<Future<Boolean>>();

			for (PestoIdP server: servers.values()){
				authentications.add(executorService.submit(() -> server.deleteAccount(username, cookies.get(server.getId()), salt, signature[server.getId()])));
			}
			for(Future<Boolean> future : authentications) {
				if(!future.get()) {
					throw new AuthenticationFailedException("Server failed to delete account");
				}
			}
			updateCurrentSessionTimes();
		} catch(Exception e) {
			signingKeys = null;
			throw new AuthenticationFailedException(e);
		}
	}

	/**
	 * Changes the users password, without changing other stored attributed on the vIdP. This requires
	 * the user to enter her old password, her new password and using a fresh MFA token (creating a
	 * new session cookie under the new key).
	 *
	 * @param username The username of the user
	 * @param oldPassword The users existing password
	 * @param newPassword The password to use in the future
	 * @param token The MFA token
	 * @param type The type of MFA token used
	 */
	@Override
	public void changePassword(String username, String oldPassword, String newPassword, String token,
			String type) throws AuthenticationFailedException, UserCreationFailedException {
		try {
			ensureActiveSession(username, oldPassword, token, type);
			byte[] newPw = newPassword.getBytes(Charsets.UTF_8);
			long salt = getFreshSalt();
			KeyPair newKeyPair = performOPRF(username, newPw, String.valueOf(salt), token, type);
			byte[] nonce = this.cryptoModule.constructNonce(username, salt);
			List<byte[]> message = new ArrayList<byte[]>();
			message.add(username.getBytes(Charsets.UTF_8));
			message.add(nonce);
			message.add(newKeyPair.getPublic().getEncoded());
			message.add(CommonRESTEndpoints.CHANGE_PASSWORD.getBytes(Charsets.UTF_8));
			int approvedCount = 0;
			List<Future<byte[]>> futures = new ArrayList<Future<byte[]>>();
			for (PestoIdP server: servers.values()){
				List<byte[]> currentMessage = new ArrayList<>();
				currentMessage.addAll(message);
				currentMessage.add(cookies.get(server.getId()));
				byte[] newSignature = this.cryptoModule.sign(newKeyPair.getPrivate(), currentMessage);
				byte[] oldSignature = this.cryptoModule.sign(signingKeys.getPrivate(), Arrays.asList(newSignature));
				futures.add(executorService.submit(() -> server.changePassword(username, cookies.get(server.getId()), newKeyPair.getPublic(), oldSignature, newSignature, salt)));
			}
			byte[][] signatures = new byte[servers.size()][];
			int it = 0;
			for(Future<byte[]> bytes : futures) {
				signatures[it] = bytes.get();
				it++;
			}
			for (int i = 0; i< servers.size(); i++){
				//Verify combined signature
				PublicKey combKey = cryptoModule.getStandardRSAkey();
				List<byte[]> input = new ArrayList<byte[]>();
				input.add(KeySerializer.serialize(newKeyPair.getPublic()).getBytes());
				if(cryptoModule.verifySignature(combKey, input, signatures[i])) {
					approvedCount++;
				}
			}
			if(approvedCount != servers.size()) {
				throw new UserCreationFailedException("Not all servers finished registration");
			}
			signingKeys = newKeyPair;
		}catch(Exception e) {
			signingKeys = null;
			throw new AuthenticationFailedException("Password change failed");
		}
	}

	@Override
	public String requestMFAChallenge(String username, String password, String type)
			throws AuthenticationFailedException {
		try{
			ensureActiveSession(username, password, null, "NO_MFA");
			long salt = getFreshSalt();
			byte[][] signature = getSignedNonceAndUid(username, salt, CommonRESTEndpoints.REQUEST_MFA);

			List<Future<String>> futures = new ArrayList<Future<String>>();

			for (PestoIdP server: servers.values()){
				futures.add(executorService.submit(() -> server.requestMFA(username, cookies.get(server.getId()), salt, type, signature[server.getId()])));
			}
			List<String> challenges = new ArrayList<String>();
			for(Future<String> future : futures) {
				challenges.add(future.get());
			}
			if(!Util.verifyIdenticalStrings(challenges)) {
				throw new AuthenticationFailedException("Differing output from vIdP");
			}
			updateCurrentSessionTimes();
			return challenges.get(0);
		} catch(Exception e) {
			signingKeys = null;
			throw new AuthenticationFailedException(e);
		}
	}

	@Override
	public void confirmMFA(String username, String password, String token, String type) throws AuthenticationFailedException {
		try{
			ensureActiveSession(username, password, null, "NO_MFA");
			long salt = getFreshSalt();
			byte[][] signature = getSignedNonceAndUid(username, salt, CommonRESTEndpoints.CONFIRM_MFA);

			List<Future<Boolean>> authentications = new ArrayList<Future<Boolean>>();
			for (PestoIdP server : servers.values()) {
				authentications.add(executorService.submit(() -> server
						.confirmMFA(username, cookies.get(server.getId()), salt, token, type,
								signature[server.getId()])));
			}
			for (Future<Boolean> future : authentications) {
				if (!future.get()) {
					throw new AuthenticationFailedException("Server failed to confirm MFA token");
				}
			}
			updateCurrentSessionTimes();
		} catch(Exception e) {
			signingKeys = null;
			throw new AuthenticationFailedException(e);
		}
	}

	@Override
	public void removeMFA(String username, String password, String token, String type) throws AuthenticationFailedException {
		try {
			ensureActiveSession(username, password, token, type);
			long salt = getFreshSalt();
			List<Future<Boolean>> authentications = new ArrayList<Future<Boolean>>();
			byte[][] signature = getSignedNonceAndUid(username, salt, CommonRESTEndpoints.REMOVE_MFA);
			for (PestoIdP server : servers.values()) {
				authentications.add(executorService.submit(() -> server
						.removeMFA(username, cookies.get(server.getId()), salt, token, type,
								signature[server.getId()])));
			}
			for (Future<Boolean> future : authentications) {
				if (!future.get()) {
					throw new AuthenticationFailedException("Server failed to remove MFA token");
				}
			}
			updateCurrentSessionTimes();
		} catch (Exception e) {
			signingKeys = null;
			throw new AuthenticationFailedException(e);
		}
	}

	protected byte[][] getSignedNonceAndUid(String username, long salt, String operation) throws Exception {
		byte[] nonce = this.cryptoModule.constructNonce(username, salt);
		byte[][] signature = signRequest(signingKeys.getPrivate(), username.getBytes(Charsets.UTF_8), nonce, operation.getBytes(
				StandardCharsets.UTF_8));
		return signature;
	}

	protected KeyPair performOPRF(String username, byte[] pw, String ssid, String mfaToken, String mfaType) throws Exception {
		BIG r = cryptoModule.getRandomNumber();
		ECP xMark = cryptoModule.hashAndMultiply(r, pw);

		Map<Integer, Future<OPRFResponse>> futures = new HashMap<>();
		for (PestoIdP server : servers.values()) {
			futures.put(server.getId(), executorService.submit(() -> server.performOPRF(ssid, username, xMark, mfaToken, mfaType)));
		}
		List<FP12> responses = new ArrayList<>();
		for ( int counter : futures.keySet()) {
			OPRFResponse resp = futures.get(counter).get();
			if (!ssid.equals(resp.getSsid())) {
				throw new UserCreationFailedException("Invalid server response");
			}
			responses.add(resp.getY());
			cookies.put(counter, Base64.decodeBase64(resp.getSessionCookie()));
		}

		byte[] privateBytes = processReplies(responses, r, username.getBytes(Charsets.UTF_8), pw);
		KeyPair keys = cryptoModule.generateKeysFromBytes(privateBytes);
		updateCurrentSessionTimes();
		return keys;
	}

	@Override
	public void clearSession() {
		this.cookies.clear();
		this.sessionStartedTimes.clear();
		for(int i=0; i< servers.size(); i++){
			sessionStartedTimes.put(i, 0l);
		}
		signingKeys = null;
	}

	protected void ensureActiveSession(String username, String password, String token, String type) throws Exception {
		long largestSessionTime = sessionStartedTimes.values().stream().mapToLong(v->v).max().getAsLong();
		if (System.currentTimeMillis() >= (largestSessionTime + sessionLength) || signingKeys == null) {
			long salt = getFreshSalt();
			byte[] nonce = this.cryptoModule.constructNonce(username, salt);
			signingKeys = performOPRF(username, password.getBytes(StandardCharsets.UTF_8), Arrays.toString(nonce), token, type);
		}
	}

	protected void updateCurrentSessionTimes()  {
		for (PestoIdP server : servers.values()) {
			sessionStartedTimes.put(server.getId(), System.currentTimeMillis());
		}
	}

	protected byte[] processReplies(List<FP12> responses, BIG r, byte[] username, byte[] password) {
		List<byte[]> toHash = new ArrayList<byte[]>();
		toHash.add(password);
		toHash.add(username);

		BIG rModInv = new BIG();
		rModInv.copy(r);
		rModInv.invmodp(new BIG(ROM.CURVE_Order));
		FP12 yMark = new FP12();
		yMark.one();
		for (FP12 current : responses) {
			yMark.mul(current);
		}
		FP12 receivedY = yMark.pow(rModInv);
		byte[] rawBytes = new byte[12* CONFIG_BIG.MODBYTES];
		receivedY.toBytes(rawBytes);
		toHash.add(rawBytes);
		
		return cryptoModule.hash(toHash);
	}

	protected byte[][] signRequest(PrivateKey privateKey, byte[] uid, byte[] nonce, byte[] operation) throws Exception{
		byte[][] output = new byte[cookies.size()][];
		for(int i = 0; i< cookies.size(); i++) {
			Signature sig = Signature.getInstance("SHA256withECDSA");
			sig.initSign(privateKey);
			sig.update(nonce);
			sig.update(uid);
			sig.update(operation);
			sig.update(cookies.get(i));
			output[i] = sig.sign();
		}
		return output;
	}
}
