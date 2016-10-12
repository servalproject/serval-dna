/**
 * Copyright (C) 2014 Serval Project Inc.
 * Copyright (C) 2016 Flinders University
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

public class JniResult implements IJniResults{
	protected String columnName=null;
	protected String command[];
	protected int result;

	void setCommand(String command[]) {
		this.command = command;
	}

	void setResult(int result) throws ServalDFailureException {
		this.result = result;
		if (result == ServalDCommand.STATUS_ERROR)
			throw new ServalDFailureException("Command \"" + ServalDCommand.toString(command)+"\" returned an error");
	}

	public int getResult(){
		return result;
	}

	@Override
	public void putString(String value) {
	}

	@Override
	public void putLong(long value) {
	}

	@Override
	public void putDouble(double value) {
	}

	@Override
	public void putHexValue(byte[] value) {
	}

	@Override
	public void putBlob(byte[] blob) {
	}

	@Override
	public void startTable(int column_count) {
	}

	@Override
	public void setColumnName(int column, String name) {
		columnName=name;
	}

	@Override
	public void endTable(int row_count) {
	}
}
