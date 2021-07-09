package eu.olympus.unit.server;

import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.UserCreationFailedException;
import eu.olympus.model.server.rest.UsernameAndPassword;
import eu.olympus.server.AbstractPasswordIdP;
import eu.olympus.server.PasswordHandler;
import eu.olympus.server.storage.InMemoryKeyDB;
import eu.olympus.server.storage.InMemoryUserPasswordDatabase;

import java.security.cert.Certificate;

import java.util.Arrays;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

public class TestAbstractPasswordIdP {

	private static final byte[] validCookie = Base64.encodeBase64("cookie".getBytes());
	
	@Test(expected = AuthenticationFailedException.class)
	public void testChangePasswordFailingWithBadCookie() throws Exception {
		InMemoryUserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		db.addUser("user", "salt", "password");
		AbstractPasswordIdP idp = new TestIdP(new PasswordHandler(db, null, new InMemoryKeyDB(), null));
		idp.changePassword(new UsernameAndPassword("user", "bad_password"), "password2",
				"cookie".getBytes());
	}
	
	@Test(expected = AuthenticationFailedException.class)
	public void testRequestMFANullPointer() throws Exception {
		InMemoryUserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		db.addUser("user", "salt", "password");
		AbstractPasswordIdP idp = new TestIdP(new PasswordHandler(db, null, new InMemoryKeyDB(), null));
		idp.requestMFA(new UsernameAndPassword("user", "password"), validCookie, null);
	}
	
	@Test(expected = AuthenticationFailedException.class)
	public void testGetAllAttributesFailingWithBadCookie() throws Exception {
		InMemoryUserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		db.addUser("user", "salt", "password");
		AbstractPasswordIdP idp = new TestIdP(new PasswordHandler(db, null, new InMemoryKeyDB(), null));
		idp.getAllAttributes("user", validCookie);
	}
	
	@Test(expected = AuthenticationFailedException.class)
	public void testDeleteAttributeFailingWithBadCookie() throws Exception {
		InMemoryUserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		db.addUser("user", "salt", "password");
		AbstractPasswordIdP idp = new TestIdP(new PasswordHandler(db, null, new InMemoryKeyDB(), null));
		idp.deleteAttribute("user", validCookie, Arrays.asList("item"));
	}

	@Test(expected = UserCreationFailedException.class)
	public void testCreateUserAndAddAttributesUserAlreadyExists() throws Exception {
		InMemoryUserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		db.addUser("user", "salt", "password");
		AbstractPasswordIdP idp = new TestIdP(new PasswordHandler(db, null, new InMemoryKeyDB(), null));
		idp.createUserAndAddAttributes(new UsernameAndPassword("user", "password"), null);
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testDeleteAccountInvalidSession() throws Exception {
		InMemoryUserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		db.addUser("user", "salt", "password");
		AbstractPasswordIdP idp = new TestIdP(new PasswordHandler(db, null, new InMemoryKeyDB(), null));
		idp.deleteAccount(new UsernameAndPassword("user", "password"), "invalidCookie".getBytes());
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testDeleteAccountInvalidPassword() throws Exception {
		InMemoryUserPasswordDatabase db = new InMemoryUserPasswordDatabase();
		db.addUser("user", "salt", "password");
		AbstractPasswordIdP idp = new TestIdP(new PasswordHandler(db, null, new InMemoryKeyDB(), null));
		idp.deleteAccount(new UsernameAndPassword("user", "badPassword"), validCookie);
	}
	
	private class TestIdP extends AbstractPasswordIdP {

		public TestIdP(PasswordHandler handler) {
			this.authenticationHandler = handler;
		}
		
		@Override
		public Certificate getCertificate() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public int getId() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public String authenticate(String username, byte[] cookie, Policy policy)
				throws AuthenticationFailedException {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public boolean validateSession(String cookie) {
			return cookie.equals("cookie");
		}
	}
}
