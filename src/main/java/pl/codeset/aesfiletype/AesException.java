package pl.codeset.aesfiletype;

public class AesException extends RuntimeException {

    public AesException(String message, Throwable cause) {
        super(message, cause);
    }

    public AesException(String message) {
        super(message);
    }
}
