package pl.codeset.aesfiletype;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;

public class AesFile {

    private final ContentProvider contentProvider;
    private byte[] password;

    private AesFile(ContentProvider contentProvider) {
        this.contentProvider = contentProvider;
    }

    public static AesFile openFromBytes(byte[] content) {
        return new AesFile(new ContentProvider() {
            @Override
            public long getStreamLength() {
                return content.length;
            }

            @Override
            public InputStream getInputStream() {
                return new ByteArrayInputStream(content);
            }
        });
    }

    public static AesFile openFromFile(Path path) {
        if (!Files.isReadable(path)) {
            throw new AesException("Unable to read from file " + path);
        }
        return new AesFile(new ContentProvider() {
            @Override
            public long getStreamLength() {
                try {
                    return Files.size(path);
                } catch (IOException e) {
                    throw new AesException("Unable to read file size.", e);
                }
            }

            @Override
            public InputStream getInputStream() {
                try {
                    return Files.newInputStream(path);
                } catch (IOException e) {
                    throw new AesException("Unable to open file stream", e);
                }
            }
        });
    }

    public AesFile usePassword(String password) {
        this.password = password.getBytes(StandardCharsets.UTF_16LE);
        return this;
    }

    public AesFile usePasswordBytes(byte[] passwordBytes) {
        this.password = passwordBytes;
        return this;
    }

    public byte[] readFileBytes() {
        try (InputStream inputStream = contentProvider.getInputStream()) {
            return contentProvider.getInputStream().readAllBytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] decryptToBytes() {
        try (InputStream inputStream = contentProvider.getInputStream()) {
            AesReader aesReader = new AesReader(contentProvider.getStreamLength(), inputStream);
            aesReader.setPassword(password);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            aesReader.decrypt(output);
            return output.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Unable to decrypt file.", e);
        }
    }

    public void decryptToFile(Path targetPath) {
        try (InputStream inputStream = contentProvider.getInputStream();
             OutputStream outputStream = Files.newOutputStream(targetPath, CREATE, TRUNCATE_EXISTING)) {
            AesReader aesReader = new AesReader(contentProvider.getStreamLength(), inputStream);
            aesReader.setPassword(password);
            aesReader.decrypt(outputStream);
        } catch (IOException e) {
            throw new AesException("Unable to decrypt file.", e);
        }
    }
}
