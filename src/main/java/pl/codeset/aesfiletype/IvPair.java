package pl.codeset.aesfiletype;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class IvPair {
    final IvParameterSpec ivSpec;
    final SecretKeySpec aesKey;

    public IvPair(byte[] iv, byte[] key) {
        ivSpec = new IvParameterSpec(iv);
        aesKey = new SecretKeySpec(key, "AES");
    }
}
