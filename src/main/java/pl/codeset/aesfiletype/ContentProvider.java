package pl.codeset.aesfiletype;

import java.io.InputStream;

interface ContentProvider {
    long getStreamLength();

    InputStream getInputStream();
}
