/**
 * Copyright (C) 2012 Serval Project, Inc.
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

public class SubscriberId extends AbstractId {

	public static final int BINARY_SIZE = 32;

	@Override
	public int getBinarySize() {
		return BINARY_SIZE;
	}

	public SubscriberId(String hex) throws InvalidHexException {
		super(hex);
	}

	public SubscriberId(ByteBuffer b) throws InvalidBinaryException {
		super(b);
	}

	public SubscriberId(byte[] binary) throws InvalidBinaryException {
		super(binary);
	}

	@Override
	public String abbreviation() {
		return "sid:" + toHex(6) + "*";
	}

	/** Return true iff this SID is a broadcast address.
	 *
	 * At the moment, a broadcast address is defined as one whose bits are all 1 except
	 * for the final 64 bits, which could be anything.  This definition may change in
	 * future, so treat this code with a grain of salt.
	 */
	public boolean isBroadcast() {
		return this.equals(broadcastSid);
	}

	public static SubscriberId broadcastSid;
	public static SubscriberId ANY;
	static {
		byte buff[] = new byte[BINARY_SIZE];
		for (int i = 0; i < BINARY_SIZE; i++)
			buff[i] = (byte) 0xff;
		try {
			broadcastSid = new SubscriberId(buff);
		} catch (InvalidBinaryException e) {
			// TODO log error?
		}

		buff = new byte[BINARY_SIZE];
		for (int i = 0; i < BINARY_SIZE; i++)
			buff[i] = (byte) 0x00;
		try {
			ANY = new SubscriberId(buff);
		} catch (InvalidBinaryException e) {
			// TODO log error?
		}
	}
}
