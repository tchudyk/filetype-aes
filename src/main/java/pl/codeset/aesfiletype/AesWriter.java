package pl.codeset.aesfiletype;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static pl.codeset.aesfiletype.AesConstraints.AES_HEADER;
import static pl.codeset.aesfiletype.AesConstraints.BLOCK_SIZE;
import static pl.codeset.aesfiletype.AesConstraints.KEY_SIZE;

class AesWriter {

    private final InputStream inputStream;

    private byte[] password;
    private final AesDigest aesDigest;
    private Cipher cipher;
    private Mac hmac;

    AesWriter(InputStream inputStream) {
        this.inputStream = inputStream;
        try {
            aesDigest = new AesDigest();
            cipher = Cipher.getInstance("AES/CBC/NoPadding");
            hmac = Mac.getInstance("HmacSHA256");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    void setPassword(byte[] password) {
        this.password = password;
    }

    void encrypt(OutputStream outputStream, FormatVersion version) throws IOException {
        try {
            outputStream.write(AES_HEADER);
            outputStream.write(version.getOctet());
            outputStream.write(0);

            if (version.isExtensionsSupported()) {
                writeExtensions(outputStream);
            }

            IvPair ivPair = prepareIvHeader(outputStream);
            encryptContent(outputStream, ivPair);

        } catch (ShortBufferException | InvalidKeyException |
                InvalidAlgorithmParameterException | BadPaddingException |
                IllegalBlockSizeException e) {
            throw new IOException("Write encrypted file exception.", e);
        }
    }

    private void writeExtensions(OutputStream outputStream) throws IOException {
        outputStream.write(0);
        outputStream.write(0);
    }

    private IvPair prepareIvHeader(OutputStream outputStream) throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] ivBytes = generateIv1();
        IvPair ivPair1 = new IvPair(ivBytes, aesDigest.generateAESKeyForPassword(ivBytes, password));
        outputStream.write(ivBytes);

        IvPair ivPair2 = new IvPair(aesDigest.generateRandomBytes(BLOCK_SIZE), aesDigest.generateRandomBytes(KEY_SIZE));
        byte[] text = new byte[BLOCK_SIZE + KEY_SIZE];
        cipher.init(Cipher.ENCRYPT_MODE, ivPair1.aesKey, ivPair1.ivSpec);
        cipher.update(ivPair2.ivSpec.getIV(), 0, BLOCK_SIZE, text);
        cipher.doFinal(ivPair2.aesKey.getEncoded(), 0, KEY_SIZE, text, BLOCK_SIZE);
        outputStream.write(text);

        hmac.init(new SecretKeySpec(ivPair1.aesKey.getEncoded(), "HmacSHA256"));
        text = hmac.doFinal(text);
        outputStream.write(text);
        return ivPair2;
    }

    private void encryptContent(OutputStream outputStream, IvPair ivPair) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, ShortBufferException {
        cipher.init(Cipher.ENCRYPT_MODE, ivPair.aesKey, ivPair.ivSpec);
        hmac.init(new SecretKeySpec(ivPair.aesKey.getEncoded(), "HmacSHA256"));

        int read, last = 0;
        byte[] block = new byte[BLOCK_SIZE];
        byte[] encrypted = new byte[BLOCK_SIZE];
        while ((read = inputStream.read(block)) > 0) {
            cipher.update(block, 0, BLOCK_SIZE, encrypted);
            hmac.update(encrypted);
            outputStream.write(encrypted);
            last = read;
        }
        last &= 0x0f;
        outputStream.write(last);
        outputStream.write(hmac.doFinal());
    }

    /**
     * Generates a pseudo-random IV based on time and this computer's MAC.
     */
    private byte[] generateIv1() {
        byte[] mac = NetworkUtils.getMacAddress();
        byte[] iv = new byte[BLOCK_SIZE];
        long time = System.currentTimeMillis();

        for (int i = 0; i < 8; i++) {
            iv[i] = (byte) (time >> (i * 8));
        }
        System.arraycopy(mac, 0, iv, 8, mac.length);
        aesDigest.digestRandomBytes(iv);
        return iv;
    }

}
