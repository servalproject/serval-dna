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

package org.servalproject.servaldna;

/**
 * Thrown when the Serval DNA interface has not behaved as expected.  This is a general class of
 * errors, and is specialised by subclasses that represent an error returned by a server command,
 * MDP protocol non-compliance, etc.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
public class ServalDInterfaceException extends Exception
{
	public ServalDInterfaceException(String message) {
		super(message);
	}

	public ServalDInterfaceException(Throwable cause) {
		super(cause);
	}

	public ServalDInterfaceException(String message, Throwable cause) {
		super(message, cause);
	}

}
