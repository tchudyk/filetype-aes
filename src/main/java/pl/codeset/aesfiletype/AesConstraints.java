package pl.codeset.aesfiletype;

import java.nio.charset.StandardCharsets;

class AesConstraints {

    static final byte[] AES_HEADER = "AES".getBytes(StandardCharsets.UTF_8);
    static final int BLOCK_SIZE = 16;
    static final int KEY_SIZE = 32;


    private AesConstraints() {
    }
}
