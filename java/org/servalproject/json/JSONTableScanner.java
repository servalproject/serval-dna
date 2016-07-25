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

package org.servalproject.json;

import java.lang.reflect.InvocationTargetException;
import java.io.IOException;
import java.util.Vector;
import java.util.Map;
import java.util.HashMap;
import java.util.HashSet;

public class JSONTableScanner {

	private static class Column {
		public boolean supported;
		public String label;
		public Class type;
		public JSONTokeniser.Narrow opts;
	}

	HashMap<String,Column> columnMap;
	Column[] columns;

	public JSONTableScanner()
	{
		columnMap = new HashMap<String,Column>();
	}

	public JSONTableScanner addColumn(String label, Class type)
	{
		return addColumn(label, type, JSONTokeniser.Narrow.NO_NULL);
	}

	public JSONTableScanner addColumn(String label, Class type, JSONTokeniser.Narrow opts)
	{
		assert !columnMap.containsKey(label);
		Column col = new Column();
		col.label = label;
		col.type = type;
		col.opts = opts;
		col.supported = JSONTokeniser.supportsNarrowTo(col.type);
		columnMap.put(label, col);
		return this;
	}

	public void consumeHeaderArray(JSONTokeniser json) throws IOException, JSONInputException
	{
		Vector<String> headers = new Vector<String>();
		json.consumeArray(headers, String.class);
		if (headers.size() < 1)
			throw new JSONInputException("malformed JSON table, empty headers array");
		columns = new Column[headers.size()];
		HashSet<String> headerSet = new HashSet<String>(columnMap.size());
		for (int i = 0; i < headers.size(); ++i) {
			String header = headers.get(i);
			if (columnMap.containsKey(header)) {
				if (headerSet.contains(header))
					throw new JSONInputException("malformed JSON table, duplicate column header: \"" + header + "\"");
				headerSet.add(header);
				columns[i] = columnMap.get(header);
			}
		}
		for (String header: columnMap.keySet())
			if (!headerSet.contains(header))
				throw new JSONInputException("malformed JSON table, missing column header: \"" + header + "\"");
	}

	@SuppressWarnings("unchecked")
	public Map<String,Object> consumeRowArray(JSONTokeniser json) throws IOException, JSONInputException
	{
		Object[] row = new Object[columns.length];
		json.consumeArray(row, JSONTokeniser.Narrow.ALLOW_NULL);
		HashMap<String,Object> rowMap = new HashMap<String,Object>(row.length);
		for (int i = 0; i < row.length; ++i) {
			Column col = columns[i];
			Object value = null;
			if (col != null) {
				try {
					if (col.supported)
						value = JSONTokeniser.narrow(row[i], col.type, col.opts);
					else {
						value = JSONTokeniser.narrow(row[i], col.opts);
						if (value != null)
							value = col.type.getConstructor(value.getClass()).newInstance(value);
					}
					rowMap.put(col.label, value);
				} catch (JSONInputException e){
					throw new JSONInputException("invalid column value: " + col.label + "; " + e.getMessage(), e);

				} catch (InvocationTargetException e) {
					throw new JSONInputException("invalid column value: " + col.label + "=\"" + value + "\"", e.getTargetException());
				} catch (Exception e) {
					throw new JSONInputException("invalid column value: " + col.label + "=\"" + value + "\"", e);
				}
			}
		}
		return rowMap;
	}
}
