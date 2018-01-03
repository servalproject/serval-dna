/**
 * Copyright (C) 2016 Flinders University
 * Copyright (C) 2011-2015 The Serval Project
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

public class BundleId extends SigningKey {

	public BundleId(String hex) throws InvalidHexException {
		super(hex);
	}

	public BundleId(ByteBuffer b) throws InvalidBinaryException {
		super(b);
	}

	public BundleId(byte[] binary) throws InvalidBinaryException {
		super(binary);
	}

	@Override
	public String getMimeType() {
		return "rhizome/bid";
	}
}
