# AES Crypt file type

This is Java implementation of AES Crypt file type.

More information about this format you can find on official website [aescrypt.com](https://www.aescrypt.com/)

License: BSD.

### Maven
Add repository to your `pom.xml`:
```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```

Add dependency:
```xml
<dependency>
    <groupId>com.github.tchudyk</groupId>
    <artifactId>filetype-aes</artifactId>
    <version>1.0.1</version>
</dependency>
```

## Usage
Encrypt file
```java
Path inputFile = Paths.get("/tmp/sample.jpg");
Path encryptedFile = Paths.get("/tmp/sample.jpg.aes");
String password = "test";

AesFile aesFile = AesFileBuilder.fromFile(inputFile)
    .usePassword(password)
    .writeToFile(encryptedFile)
    .build();
```


Decrypt file
```java
Path encryptedFile = Paths.get("/tmp/ja.jpg.aes");
Path decryptPath = Paths.get("/tmp/t.png");
String password = "test";

AesFile.openFromFile(encryptedFile)
    .usePassword(password)
    .decryptToFile(decryptPath);
```
