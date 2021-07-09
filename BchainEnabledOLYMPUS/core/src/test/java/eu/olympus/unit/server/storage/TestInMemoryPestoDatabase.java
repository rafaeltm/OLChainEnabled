package eu.olympus.unit.server.storage;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;
import eu.olympus.TestParameters;
import eu.olympus.model.Attribute;
import eu.olympus.model.MFAInformation;

import org.junit.Test;

import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.storage.InMemoryPestoDatabase;

public class TestInMemoryPestoDatabase {
	
	long salt = 12345;

	@Test
	public void testBasics() {
		PestoDatabase db = new InMemoryPestoDatabase();
		db.addUser("user1", TestParameters.getRSAPublicKey1(), salt);
		assertTrue(db.hasUser("user1"));
		assertEquals(TestParameters.getRSAPublicKey1(), db.getUserKey("user1"));
		assertEquals(salt, db.getLastSalt("user1"));
		db.setSalt("user1", 100000);
		assertEquals(100000, db.getLastSalt("user1"));
		
		boolean successfulDelete = db.deleteUser("user1");
		assertTrue(successfulDelete);
		assertFalse(db.hasUser("user1"));
		assertFalse(db.deleteUser("user1"));
	}
	
	@Test
	public void testAttributes() {
		PestoDatabase db = new InMemoryPestoDatabase();
		db.addUser("user1", TestParameters.getRSAPublicKey1(), salt);
		assertEquals(0, db.getAttributes("user1").size());
		
		db.addAttribute("user1", "name", new Attribute("John"));
		assertEquals(1, db.getAttributes("user1").size());
		assertEquals(new Attribute("John"), db.getAttributes("user1").get("name"));
		
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("age", new Attribute(25));
		attributes.put("nationality", new Attribute("US"));
		db.addAttributes("user1", attributes);
		
		assertEquals(3, db.getAttributes("user1").size());
		assertEquals(new Attribute("John"), db.getAttributes("user1").get("name"));
		assertEquals(new Attribute(25), db.getAttributes("user1").get("age"));
		assertEquals(new Attribute("US"), db.getAttributes("user1").get("nationality"));

		assertTrue(db.deleteAttribute("user1", "name"));
		assertEquals(2, db.getAttributes("user1").size());
		
		assertFalse(db.deleteAttribute("user1", "name"));
		
		assertFalse(db.deleteAttribute("user2", "age"));
	}
	
	@Test
	public void testChangeKey() {
		PestoDatabase db = new InMemoryPestoDatabase();
		db.addUser("user1", TestParameters.getRSAPublicKey1(), salt);
		assertEquals(0, db.getAttributes("user1").size());
		
		db.addAttribute("user1", "name", new Attribute("John"));
		assertEquals(1, db.getAttributes("user1").size());
		assertEquals(new Attribute("John"), db.getAttributes("user1").get("name"));
		assertEquals(TestParameters.getRSAPublicKey1(), db.getUserKey("user1"));
		assertEquals(salt, db.getLastSalt("user1"));
		
		db.replaceUserKey("user1", TestParameters.getRSAPublicKey2(), 1000);
		
		assertEquals(1, db.getAttributes("user1").size());
		assertEquals(new Attribute("John"), db.getAttributes("user1").get("name"));
		assertEquals(TestParameters.getRSAPublicKey2(), db.getUserKey("user1"));
		assertEquals(1000, db.getLastSalt("user1"));		
	}
	
	@Test
	public void testMFA() {
		PestoDatabase db = new InMemoryPestoDatabase();
		db.addUser("user1", TestParameters.getECPublicKey1(), salt);
		db.assignMFASecret("user1", "GOOGLE_AUTHENTICATOR", "secret");
		MFAInformation info = db.getMFAInformation("user1").get("GOOGLE_AUTHENTICATOR");
		assertFalse(info.isActivated());
		db.activateMFA("user1", "GOOGLE_AUTHENTICATOR");
		assertTrue(db.getMFAInformation("user1").get("GOOGLE_AUTHENTICATOR").isActivated());
		db.deleteMFA("user1", "GOOGLE_AUTHENTICATOR");
		assertFalse(db.getMFAInformation("user1").get("GOOGLE_AUTHENTICATOR").isActivated());
		db.deleteMFA("user1", "NONE");
		assertNull(db.getMFAInformation("user1").get("NONE"));
		
	}
}
