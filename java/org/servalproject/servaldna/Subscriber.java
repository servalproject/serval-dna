package org.servalproject.servaldna;

import java.nio.ByteBuffer;

/**
 * Created by jeremy on 22/06/16.
 */
public final class Subscriber {
    public final SubscriberId sid;
    public final SigningKey signingKey;
    public final boolean combined;

    public Subscriber(SubscriberId sid){
        this(sid, null, false);
    }

    public Subscriber(SubscriberId sid, SigningKey signingKey, boolean combined){
        this.sid = sid;
        this.signingKey = signingKey;
        this.combined = combined;
    }

    public Subscriber(ByteBuffer buff) throws AbstractId.InvalidBinaryException {
        SubscriberId sid = new SubscriberId(buff);
        SigningKey signingKey = new SigningKey(buff);
        int signKeyFlags = 0xFF & (int)buff.get();
        if ((signKeyFlags&0x01)==0x00)
            signingKey = null;
        this.sid = sid;
        this.signingKey = signingKey;
        this.combined = (signKeyFlags&0x02)==0x02;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Subscriber that = (Subscriber) o;

        return sid.equals(that.sid);
    }

    @Override
    public int hashCode() {
        return sid.hashCode();
    }

    @Override
    public String toString(){
        return sid.toString();
    }
}
