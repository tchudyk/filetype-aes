package pl.codeset.aesfiletype;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;

public class AesFileBuilder {

    private final WriteContentProvider streamProvider;
    private byte[] password;
    private Path targetPath;

    private AesFileBuilder(WriteContentProvider streamProvider) {
        this.streamProvider = streamProvider;
    }

    public static AesFileBuilder fromBytes(byte[] bytes) {
        return new AesFileBuilder(() -> new ByteArrayInputStream(bytes));
    }

    public static AesFileBuilder fromFile(Path path) {
        return new AesFileBuilder(() -> {
            try {
                return Files.newInputStream(path, StandardOpenOption.READ);
            } catch (IOException e) {
                throw new AesException("Unable to open file stream.", e);
            }
        });
    }

    public AesFileBuilder usePassword(String password) {
        this.password = password.getBytes(StandardCharsets.UTF_16LE);
        return this;
    }

    public AesFileBuilder usePasswordBytes(byte[] passwordBytes) {
        this.password = passwordBytes;
        return this;
    }

    public AesFileBuilder writeToFile(Path targetPath) {
        this.targetPath = targetPath;
        return this;
    }

    public AesFile build() {
        try (InputStream inputStream = streamProvider.getInputStream()) {
            AesWriter aesWriter = new AesWriter(inputStream);
            aesWriter.setPassword(password);

            if (targetPath != null) {
                try (OutputStream out = Files.newOutputStream(targetPath, CREATE, TRUNCATE_EXISTING)) {
                    aesWriter.encrypt(out, FormatVersion.V_2);
                    return AesFile.openFromFile(targetPath)
                            .usePasswordBytes(password);
                } catch (IOException e) {
                    throw new AesException("Unable to encrypt file.", e);
                }
            } else {
                try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                    aesWriter.encrypt(out, FormatVersion.V_2);
                    return AesFile.openFromBytes(out.toByteArray())
                            .usePasswordBytes(password);
                } catch (IOException e) {
                    throw new AesException("Unable to encrypt file.", e);
                }
            }

        } catch (IOException e) {
            throw new AesException("Unable to read input stream.", e);
        }
    }

    private interface WriteContentProvider extends ContentProvider {
        @Override
        default long getStreamLength() {
            return 0;
        }
    }
}
