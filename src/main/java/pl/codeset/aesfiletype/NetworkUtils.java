package pl.codeset.aesfiletype;

import java.net.NetworkInterface;
import java.util.Enumeration;

public class NetworkUtils {

    private static final byte[] DEFAULT_MAC =
            {0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};

    static byte[] getMacAddress() {
        byte[] mac = null;
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (mac == null && interfaces.hasMoreElements()) {
                mac = interfaces.nextElement().getHardwareAddress();
            }
        } catch (Exception e) {
        }
        if (mac == null) {
            mac = DEFAULT_MAC;
        }
        return mac;
    }
}
