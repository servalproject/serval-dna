/**
 * Copyright (C) 2016-2017 Flinders University
 *
 * This file is part of Serval Software (http://www.servalproject.org)
 *
 * Serval Software is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This source code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this source code; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package org.servalproject.servaldna;

import java.nio.ByteBuffer;

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

    public Subscriber(byte[] sidBytes, byte[] signBytes, boolean combined) throws AbstractId.InvalidBinaryException {
        sid = new SubscriberId(sidBytes);
        signingKey = signBytes==null ? null : new SigningKey(signBytes);
        this.combined = combined;
    }

    public Subscriber(ByteBuffer buff) throws AbstractId.InvalidBinaryException {
        SubscriberId sid = new SubscriberId(buff);
        int signKeyFlags = 0xFF & (int)buff.get();
        if ((signKeyFlags&0x01)==0x00)
            signingKey = null;
        else
            signingKey = new SigningKey(buff);
        this.sid = sid;
        this.combined = (signKeyFlags&0x02)==0x02;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Subscriber that = (Subscriber) o;
        if (that.signingKey!=null && this.signingKey!=null)
            return signingKey.equals(that.signingKey);

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
