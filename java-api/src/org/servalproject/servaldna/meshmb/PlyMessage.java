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

package org.servalproject.servaldna.meshmb;

import java.util.Date;

public class PlyMessage implements Comparable<PlyMessage>{

    public final long _row;
    public final long offset;
    public final String token;
    public final long timestamp;
    public final Date date;
    public final String text;

    public PlyMessage(long _row, long offset, String token, long timestamp, String text){
        this._row = _row;
        this.offset = offset;
        this.token = token;
        this.timestamp = timestamp;
        this.date = new Date(timestamp * 1000);
        this.text = text;
    }

    @Override
    public int compareTo(PlyMessage plyMessage) {
        if (this.offset == plyMessage.offset)
            return 0;
        return (this.offset < plyMessage.offset) ? 1 : -1;
    }
}
