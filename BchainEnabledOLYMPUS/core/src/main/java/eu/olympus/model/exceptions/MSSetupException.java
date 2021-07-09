package eu.olympus.model.exceptions;

public class MSSetupException extends Exception{
    public MSSetupException() {
    }

    public MSSetupException(Exception e) {
        super(e);
    }

    public MSSetupException(String string) {
        super(string);
    }
}
