package org.servalproject.servaldna;

import java.nio.ByteBuffer;

/**
 * Created by jeremy on 22/06/16.
 */
public class SigningKey extends AbstractId {
    public SigningKey(String hex) throws InvalidHexException {
        super(hex);
    }

    public SigningKey(ByteBuffer b) throws InvalidBinaryException {
        super(b);
    }

    public SigningKey(byte[] binary) throws InvalidBinaryException {
        super(binary);
    }

    public static final int BINARY_SIZE = 32;

    @Override
    public int getBinarySize() {
        return BINARY_SIZE;
    }
}
