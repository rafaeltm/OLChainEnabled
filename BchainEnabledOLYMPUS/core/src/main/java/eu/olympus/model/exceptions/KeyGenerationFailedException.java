package eu.olympus.model.exceptions;

public class KeyGenerationFailedException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1166242502681285887L;

	public KeyGenerationFailedException(Exception e) {
		super(e);
	}

	public KeyGenerationFailedException() {
		super();
	}

}
