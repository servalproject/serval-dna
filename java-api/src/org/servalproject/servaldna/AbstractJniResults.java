/**
 * Copyright (C) 2016 Flinders University
 * Copyright (C) 2014-2015 Serval Project Inc.
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

public abstract class AbstractJniResults implements IJniResults {

	@Override
	public void putString(String value) {
		putBlob((value != null) ? value.getBytes() : null);
	}

	@Override
	public void putLong(long value) {
		putBlob(Long.toString(value).getBytes());
	}

	@Override
	public void putDouble(double value) {
		putBlob(Double.toString(value).getBytes());
	}

	@Override
	public void putHexValue(byte[] value) {
		putBlob(value);
	}

	@Override
	public abstract void putBlob(byte[] blob);

	@Override
	public void startTable(int column_count) {
		putBlob(Integer.toString(column_count).getBytes());
	}

	@Override
	public void setColumnName(int i, String name) {
		putBlob(name.getBytes());
	}

	@Override
	public void endTable(int row_count) {
	}
}
