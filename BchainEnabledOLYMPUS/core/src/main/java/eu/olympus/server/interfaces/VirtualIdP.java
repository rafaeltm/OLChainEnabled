package eu.olympus.server.interfaces;

import java.security.cert.Certificate;

/**
 * The external interface for the IdP. This should be implemented
 * as a REST interface by all partial IdPs.
 */
public interface VirtualIdP {

	/**
	 * Return the  public key share for this IdP.
	 * @return
	 */
	public Certificate getCertificate();

	/**
	 * Return the ID used to identify this IdP
	 */
	public int getId();

}
