package pl.codeset.aesfiletype;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

class AesDigest {

    private final MessageDigest digest;
    private final SecureRandom random;

    AesDigest() throws NoSuchAlgorithmException {
        digest = MessageDigest.getInstance("SHA-256");
        random = SecureRandom.getInstance("SHA1PRNG");
    }

    void digestRandomBytes(byte[] bytes) {
        digest.reset();
        digest.update(bytes);
        for (int i = 0; i < 256; i++) {
            random.nextBytes(bytes);
            digest.update(bytes);
        }
        System.arraycopy(digest.digest(), 0, bytes, 0, bytes.length);
    }

    byte[] generateAESKeyForPassword(byte[] iv, byte[] password) {
        byte[] aesKey = new byte[32];
        System.arraycopy(iv, 0, aesKey, 0, iv.length);
        for (int i = 0; i < 8192; i++) {
            digest.reset();
            digest.update(aesKey);
            digest.update(password);
            aesKey = digest.digest();
        }
        return aesKey;
    }

    byte[] generateRandomBytes(int len) {
        byte[] bytes = new byte[len];
        random.nextBytes(bytes);
        digestRandomBytes(bytes);
        return bytes;
    }
}
