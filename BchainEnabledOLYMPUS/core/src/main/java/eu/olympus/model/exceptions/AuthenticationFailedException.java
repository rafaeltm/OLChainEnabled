package eu.olympus.model.exceptions;

public class AuthenticationFailedException extends Exception {

	public AuthenticationFailedException(String string) {
		super(string);
	}

	public AuthenticationFailedException(Exception e) {
		super(e);
	}

	/**
	 * 
	 */
	private static final long serialVersionUID = 7483158635274840693L;

}
