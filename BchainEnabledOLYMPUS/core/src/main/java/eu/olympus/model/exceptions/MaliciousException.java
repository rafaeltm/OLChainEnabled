package eu.olympus.model.exceptions;

public class MaliciousException extends RuntimeException {
  public MaliciousException() {
    super();
  }

  public MaliciousException(Exception e) {
    super(e);
  }

  public MaliciousException(String m) {
    super(m);
  }
}
