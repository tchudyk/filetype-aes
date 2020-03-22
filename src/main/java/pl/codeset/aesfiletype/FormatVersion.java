package pl.codeset.aesfiletype;

public enum FormatVersion {
    V_1(1, false),
    V_2(2, true);

    private final int octet;
    private boolean extensionsSupport;

    FormatVersion(int octet, boolean extensionsSupport) {
        this.octet = octet;
        this.extensionsSupport = extensionsSupport;
    }

    int getOctet() {
        return octet;
    }

    public boolean isExtensionsSupported() {
        return extensionsSupport;
    }
}
