/**
 * Copyright (C) 2014 Serval Project Inc.
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

package org.servalproject.servaldna.rhizome;

import org.servalproject.servaldna.ServalDInterfaceException;

/* This enum is a direct isomorphism from the C "enum rhizome_payload_status" defined in rhizome.h.
 */
public enum RhizomePayloadStatus {
    ERROR(-1), 		// unexpected error (underlying failure)
    EMPTY(0),		// payload is empty (zero length)
    NEW(1),			// payload is not yet in store (added)
    STORED(2),		// payload is already in store
    WRONG_SIZE(3),	// payload's size does not match manifest
    WRONG_HASH(4),	// payload's hash does not match manifest
    CRYPTO_FAIL(5),	// cannot encrypt/decrypt (payload key unknown)
    TOO_BIG(6),		// payload will never fit in our store
    EVICTED(7)		// other payloads in our store are more important
	;

	final public int code;

	private RhizomePayloadStatus(int code) {
		this.code = code;
	}

	public static RhizomePayloadStatus fromCode(int code) throws InvalidException
	{
		RhizomePayloadStatus status = null;
		switch (code) {
		case -1: status = ERROR; break;
		case 0: status = EMPTY; break;
		case 1: status = NEW; break;
		case 2: status = STORED; break;
		case 3: status = WRONG_SIZE; break;
		case 4: status = WRONG_HASH; break;
		case 5: status = CRYPTO_FAIL; break;
		case 6: status = TOO_BIG; break;
		case 7: status = EVICTED; break;
		default: throw new InvalidException(code);
		}
		assert status.code == code;
		return status;
	}

	public static class InvalidException extends ServalDInterfaceException
	{
		public InvalidException(int code) {
			super("invalid Rhizome payload status code = " + code);
		}
	}

}
