package pl.codeset.aesfiletype;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class AesFileTest {

    @Test
    void encryptDecryptTest(@TempDir Path tempDir) {

        byte[] inputBytes = "Test...".getBytes(StandardCharsets.UTF_8);
        AesFileBuilder.fromBytes(inputBytes)
                .usePassword("test")
                .writeToFile(tempDir.resolve("encrypted.aes"))
                .build();

        AesFile loadedFile = AesFile.openFromFile(tempDir.resolve("encrypted.aes"))
                .usePassword("test");

        byte[] bytes = loadedFile.decryptToBytes();

        assertArrayEquals(inputBytes, bytes);
    }

    @Test
    void encryptDecryptEmptyTest(@TempDir Path tempDir) {

        byte[] inputBytes = "".getBytes(StandardCharsets.UTF_8);
        AesFileBuilder.fromBytes(inputBytes)
                .usePassword("test")
                .writeToFile(tempDir.resolve("encrypted.aes"))
                .build();

        AesFile loadedFile = AesFile.openFromFile(tempDir.resolve("encrypted.aes"))
                .usePassword("test");

        byte[] bytes = loadedFile.decryptToBytes();

        assertArrayEquals(inputBytes, bytes);
    }
}