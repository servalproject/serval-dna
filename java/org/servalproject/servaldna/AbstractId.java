/**
 * Copyright (C) 2011 The Serval Project
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

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

public abstract class AbstractId {

	abstract int getBinarySize();

	public static class InvalidHexException extends Exception {
		private static final long serialVersionUID = 1L;

		private InvalidHexException(AbstractId id, String message) {
			super(id.getClass().getName() + ": " + message);
		}
	}

	public static class InvalidBinaryException extends Exception {
		private static final long serialVersionUID = 1L;

		private InvalidBinaryException(AbstractId id, String message) {
			super(id.getClass().getName() + ": " + message);
		}
	}

	private final byte[] binary;

	public AbstractId(String hex) throws InvalidHexException {
		if (hex==null)
			throw new InvalidHexException(this, "null is not a invalid hex value");
		if (hex.length() != getBinarySize()*2)
			throw new InvalidHexException(this, "invalid length " + hex.length() + " (should be " + (getBinarySize() * 2) + ") of '" + hex + "'");
		binary = new byte[getBinarySize()];
		int j = 0;
		for (int i = 0; i != binary.length; i++) {
			int d1 = Character.digit(hex.charAt(j++), 16);
			int d2 = Character.digit(hex.charAt(j++), 16);
			if (d1 == -1 || d2 == -1)
				throw new InvalidHexException(this, "non-hex digit in '" + hex + "'");
			binary[i] = (byte) ((d1 << 4) | d2);
		}
	}

	public AbstractId(ByteBuffer b) throws InvalidBinaryException {
		this.binary = new byte[getBinarySize()];
		try {
			b.get(this.binary);
		}
		catch (BufferUnderflowException e) {
			throw new InvalidBinaryException(this, "not enough bytes (expecting " + getBinarySize() + ")");
		}
	}

	public AbstractId(byte[] binary) throws InvalidBinaryException {
		if (binary.length != getBinarySize())
			throw new InvalidBinaryException(this, "invalid number of bytes (" + binary.length + "), should be " + getBinarySize());
		this.binary = binary;
	}

	@Override
	public boolean equals(Object other) {
		// must be the exact same type with the same binary contents to be considered equal
		if (other==null)
			return false;
		if (other==this)
			return true;
		if (other.getClass() == this.getClass()) {
			AbstractId oBinary = (AbstractId) other;
			for (int i = 0; i < this.binary.length; i++)
				if (this.binary[i] != oBinary.binary[i])
					return false;
			return true;
		}
		return false;
	}

	@Override
	public int hashCode() {
		int hashCode = 0;
		for (int i = 0; i < this.binary.length; i++)
			hashCode = (hashCode << 8 | hashCode >>> 24) ^ this.binary[i];
		return hashCode;
	}

	public void toByteBuffer(ByteBuffer buff){
		buff.put(this.binary);
	}

	public String toHex(int offset, int len) {
		StringBuilder sb = new StringBuilder();
		for (int i = offset; i < offset + len && i < binary.length; i++) {
			sb.append(Character.forDigit(((binary[i]) & 0xf0) >> 4, 16));
			sb.append(Character.forDigit((binary[i]) & 0x0f, 16));
		}
		return sb.toString().toUpperCase();
	}

	public String toHex(int len) {
		return toHex(0, len);
	}

	public String toHex() {
		return toHex(0, binary.length);
	}

	public String abbreviation() {
		return toHex(0, 4);
	}


	@Override
	public String toString() {
		return toHex();
	}

}
