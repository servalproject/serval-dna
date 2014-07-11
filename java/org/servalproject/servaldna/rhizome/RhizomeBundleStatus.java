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

/* This enum is a direct isomorphism from the C "enum rhizome_bundle_status" defined in rhizome.h.
 */
public enum RhizomeBundleStatus {
    ERROR(-1), 			// internal error
    NEW(0),				// bundle is newer than store
    SAME(1),			// same version already in store
    DUPLICATE(2),		// equivalent bundle already in store
    OLD(3),				// newer version already in store
    INVALID(4),			// manifest is invalid
    FAKE(5),			// manifest signature not valid
    INCONSISTENT(6),	// manifest filesize/filehash does not match supplied payload
    NO_ROOM(7),			// doesn't fit; store may contain more important bundles
    READONLY(8)			// cannot modify manifest; secret unknown
	;

	final public int code;

	private RhizomeBundleStatus(int code) {
		this.code = code;
	}

	public static RhizomeBundleStatus fromCode(int code) throws InvalidException
	{
		RhizomeBundleStatus status = null;
		switch (code) {
		case -1: status = ERROR; break;
		case 0: status = NEW; break;
		case 1: status = SAME; break;
		case 2: status = DUPLICATE; break;
		case 3: status = OLD; break;
		case 4: status = INVALID; break;
		case 5: status = FAKE; break;
		case 6: status = INCONSISTENT; break;
		case 7: status = NO_ROOM; break;
		case 8: status = READONLY; break;
		default: throw new InvalidException(code);
		}
		assert status.code == code;
		return status;
	}

	public static class InvalidException extends ServalDInterfaceException
	{
		public InvalidException(int code) {
			super("invalid Rhizome bundle status code = " + code);
		}
	}

}
