/**
 * Copyright (C) 2014-2015 Serval Project Inc.
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

public abstract class JniResultList<T extends JniResult> implements IJniResults {
	private String names[];
	private int column =-1;
	private int column_count = -1;
	private T currentRow;
	private AsyncResult<T> results;

	public JniResultList(AsyncResult<T> results){
		this.results = results;
	}
	public abstract T create();

	@Override
	public void startTable(int column_count) {
		names = new String[column_count];
		this.column_count = column_count;
	}

	@Override
	public void setColumnName(int column, String name) {
		names[column]=name;
	}

	@Override
	public void endTable(int row_count) {
	}

	private void prepareCol(){
		column++;
		if (column==0)
			currentRow = create();
		currentRow.columnName = names[column];
	}

	private void endCol(){
		if (column+1>=column_count){
			if (currentRow!=null)
				results.result(currentRow);
			currentRow=null;
			column=-1;
		}
	}

	@Override
	public void putString(String value) {
		prepareCol();
		currentRow.putString(value);
		endCol();
	}

	@Override
	public void putLong(long value) {
		prepareCol();
		currentRow.putLong(value);
		endCol();
	}

	@Override
	public void putDouble(double value) {
		prepareCol();
		currentRow.putDouble(value);
		endCol();
	}

	@Override
	public void putBlob(byte[] blob) {
		prepareCol();
		currentRow.putBlob(blob);
		endCol();
	}

	@Override
	public void putHexValue(byte[] value) {
		prepareCol();
		currentRow.putBlob(value);
		endCol();
	}
}
