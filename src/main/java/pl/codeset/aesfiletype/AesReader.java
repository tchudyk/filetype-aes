package pl.codeset.aesfiletype;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static pl.codeset.aesfiletype.AesConstraints.BLOCK_SIZE;
import static pl.codeset.aesfiletype.AesConstraints.KEY_SIZE;

class AesReader {

    private final long streamLength;
    private int bytesRead = 0;
    private InputStream inputStream;
    private List<byte[]> extensions;
    private byte[] password;

    private Cipher cipher;
    private Mac hmac;
    private AesDigest aesDigest;

    AesReader(long streamLength, InputStream inputStream) {
        this.streamLength = streamLength;
        this.inputStream = inputStream;

        try {
            aesDigest = new AesDigest();
            cipher = Cipher.getInstance("AES/CBC/NoPadding");
            hmac = Mac.getInstance("HmacSHA256");
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    void setPassword(byte[] password) {
        this.password = password;
    }

    private void readHeaders() throws IOException {
        byte[] bytes = inputStream.readNBytes(3);
        bytesRead += 3;
        if (!Arrays.equals(bytes, AesConstraints.AES_HEADER)) {
            throw new IOException("Invalid file header.");
        }

        int formatVersion = inputStream.read();
        bytesRead += 1;
        if (formatVersion < 1 || formatVersion > 2) {
            throw new IOException("Unsupported format version: " + formatVersion);
        }

        inputStream.skip(1);
        bytesRead += 1;
        List<byte[]> extensions = new ArrayList<>();
        if (formatVersion == 2) {    // Extensions.
            short len;
            do {
                ByteBuffer buff = ByteBuffer.wrap(inputStream.readNBytes(2));
                len = buff.getShort();
                bytesRead += 2 + len;
                extensions.add(inputStream.readNBytes(len));
            } while (len != 0);
        }
        this.extensions = Collections.unmodifiableList(extensions);
    }

    List<byte[]> getExtensions() throws IOException {
        if (extensions == null) {
            readHeaders();
        }
        return extensions;
    }

    void decrypt(OutputStream outputStream) throws IOException {
        try {
            if (extensions == null) {
                readHeaders();
            }

            byte[] iv1 = inputStream.readNBytes(16);
            byte[] backupVector = inputStream.readNBytes(48);
            byte[] hMac1 = inputStream.readNBytes(32);
            bytesRead += 16 + 48 + 32;

            IvPair ivPair1 = new IvPair(iv1, aesDigest.generateAESKeyForPassword(iv1, password));

            cipher.init(Cipher.DECRYPT_MODE, ivPair1.aesKey, ivPair1.ivSpec);
            byte[] data = cipher.doFinal(backupVector);

            IvParameterSpec ivSpec2 = new IvParameterSpec(data, 0, BLOCK_SIZE);
            SecretKeySpec aesKey2 = new SecretKeySpec(data, BLOCK_SIZE, KEY_SIZE, "AES");

            hmac.init(new SecretKeySpec(ivPair1.aesKey.getEncoded(), "HmacSHA256"));
            backupVector = hmac.doFinal(backupVector);

            if (!Arrays.equals(backupVector, hMac1)) {
                throw new AesPasswordException("Corrupted file or incorrect password");
            }

            // Read content
            byte[] read;
            byte[] decrypted = new byte[BLOCK_SIZE];
            long expectedPayloadSize = streamLength - bytesRead - 33;
            int readPayload = 0;
            cipher.init(Cipher.DECRYPT_MODE, aesKey2, ivSpec2);
            hmac.init(new SecretKeySpec(aesKey2.getEncoded(), "HmacSHA256"));
            do {
                read = inputStream.readNBytes(Math.min(BLOCK_SIZE, (int) (expectedPayloadSize - readPayload)));
                bytesRead += read.length;
                readPayload += read.length;

                cipher.update(read, 0, BLOCK_SIZE, decrypted);
                hmac.update(read, 0, BLOCK_SIZE);

                int readLength = read.length;
                if (readPayload >= expectedPayloadSize) {
                    // After read last block limit it size to bytes with data
                    int last = inputStream.read(); // In this byte we have info about size of data in last block
                    readLength = (last > 0 ? last : BLOCK_SIZE);
                }

                outputStream.write(decrypted, 0, readLength);
            } while (readPayload < expectedPayloadSize);

            outputStream.write(cipher.doFinal());

            // End of file...
            byte[] hmac2 = inputStream.readNBytes(32);

            byte[] expectedHmac = hmac.doFinal();
            if (!Arrays.equals(expectedHmac, hmac2)) {
                throw new IOException("Message has been altered or password incorrect");
            }
        } catch (IllegalBlockSizeException | BadPaddingException |
                InvalidAlgorithmParameterException | InvalidKeyException |
                ShortBufferException e) {
            throw new IOException("Read encrypted content exception.", e);
        }
    }
}
