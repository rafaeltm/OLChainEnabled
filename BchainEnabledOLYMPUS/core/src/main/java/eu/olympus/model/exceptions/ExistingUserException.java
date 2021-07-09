package eu.olympus.model.exceptions;

public class ExistingUserException extends UserCreationFailedException {

	public ExistingUserException() {
		super();
	}
	
	public ExistingUserException(Exception e) {
		super(e);
	}

	/**
	 * 
	 */
	private static final long serialVersionUID = -108699581843224108L;

}
