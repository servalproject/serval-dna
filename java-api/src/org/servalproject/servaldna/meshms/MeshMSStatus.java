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

package org.servalproject.servaldna.meshms;

import org.servalproject.servaldna.ServalDInterfaceException;

/* This enum is a direct isomorphism from the C "enum meshms_result" defined in meshms.h.
 */
public enum MeshMSStatus {
    ERROR(-1), 			// unexpected error (underlying failure)
    OK(0),				// operation succeeded, no bundle changed
    UPDATED(1),			// operation succeeded, bundle updated
    SID_LOCKED(2),		// cannot decode or send messages for that SID
    PROTOCOL_FAULT(3),	// missing or faulty ply bundle
	;

	final public int code;

	private MeshMSStatus(int code) {
		this.code = code;
	}

	public static MeshMSStatus fromCode(int code) throws InvalidException
	{
		MeshMSStatus status = null;
		switch (code) {
		case -1: status = ERROR; break;
		case 0: status = OK; break;
		case 1: status = UPDATED; break;
		case 2: status = SID_LOCKED; break;
		case 3: status = PROTOCOL_FAULT; break;
		default: throw new InvalidException(code);
		}
		assert status.code == code;
		return status;
	}

	public static class InvalidException extends ServalDInterfaceException
	{
		public InvalidException(int code) {
			super("invalid MeshMS status code = " + code);
		}
	}

}
