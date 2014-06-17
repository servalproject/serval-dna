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

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Vector;
import java.net.HttpURLConnection;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SubscriberId;
import org.servalproject.json.JSONTokeniser;
import org.servalproject.json.JSONInputException;

public class MeshMSConversationList {

	private ServalDHttpConnectionFactory httpConnector;
	private SubscriberId sid;
	private HttpURLConnection httpConnection;
	private JSONTokeniser json;
	private Vector<String> headers;
	int columnIndex__id;
	int columnIndex_my_sid;
	int columnIndex_their_sid;
	int columnIndex_read;
	int columnIndex_last_message;
	int columnIndex_read_offset;
	int rowCount;

	public MeshMSConversationList(ServalDHttpConnectionFactory connector, SubscriberId sid)
	{
		this.httpConnector = connector;
		this.sid = sid;
	}

	public boolean isConnected()
	{
		return this.json != null;
	}

	public void connect() throws ServalDInterfaceException, IOException
	{
		try {
			columnIndex__id = -1;
			columnIndex_my_sid = -1;
			columnIndex_their_sid = -1;
			columnIndex_read = -1;
			columnIndex_last_message = -1;
			columnIndex_read_offset = -1;
			rowCount = 0;
			httpConnection = httpConnector.newServalDHttpConnection("/restful/meshms/" + sid.toHex() + "/conversationlist.json");
			httpConnection.connect();
			if (httpConnection.getResponseCode() != HttpURLConnection.HTTP_OK)
				throw new ServalDInterfaceException("unexpected HTTP response code: " + httpConnection.getResponseCode());
			if (!httpConnection.getContentType().equals("application/json"))
				throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + httpConnection.getContentType());
			json = new JSONTokeniser(new InputStreamReader(httpConnection.getInputStream(), "US-ASCII"));
			json = new JSONTokeniser(new InputStreamReader(httpConnection.getInputStream(), "US-ASCII"));
			json.consume(JSONTokeniser.Token.START_OBJECT);
			json.consume("header");
			json.consume(JSONTokeniser.Token.COLON);
			headers = new Vector<String>();
			json.consumeArray(headers, String.class);
			if (headers.size() < 1)
				throw new ServalDInterfaceException("empty JSON headers array");
			for (int i = 0; i < headers.size(); ++i) {
				String header = headers.get(i);
				if (header.equals("_id"))
					columnIndex__id = i;
				else if (header.equals("my_sid"))
					columnIndex_my_sid = i;
				else if (header.equals("their_sid"))
					columnIndex_their_sid = i;
				else if (header.equals("read"))
					columnIndex_read = i;
				else if (header.equals("last_message"))
					columnIndex_last_message = i;
				else if (header.equals("read_offset"))
					columnIndex_read_offset = i;
			}
			if (columnIndex__id == -1)
				throw new ServalDInterfaceException("missing JSON column: _id");
			if (columnIndex_my_sid == -1)
				throw new ServalDInterfaceException("missing JSON column: my_sid");
			if (columnIndex_their_sid == -1)
				throw new ServalDInterfaceException("missing JSON column: their_sid");
			if (columnIndex_read == -1)
				throw new ServalDInterfaceException("missing JSON column: read");
			if (columnIndex_last_message == -1)
				throw new ServalDInterfaceException("missing JSON column: last_message");
			if (columnIndex_read_offset == -1)
				throw new ServalDInterfaceException("missing JSON column: read_offset");
			json.consume(JSONTokeniser.Token.COMMA);
			json.consume("rows");
			json.consume(JSONTokeniser.Token.COLON);
			json.consume(JSONTokeniser.Token.START_ARRAY);
		}
		catch (JSONInputException e) {
			throw new ServalDInterfaceException(e);
		}
	}

	public MeshMSConversation nextConversation() throws ServalDInterfaceException, IOException
	{
		try {
			Object tok = json.nextToken();
			if (tok == JSONTokeniser.Token.END_ARRAY) {
				json.consume(JSONTokeniser.Token.END_OBJECT);
				json.consume(JSONTokeniser.Token.EOF);
				return null;
			}
			if (rowCount != 0) {
				JSONTokeniser.match(tok, JSONTokeniser.Token.COMMA);
				tok = json.nextToken();
			}
			JSONTokeniser.match(tok, JSONTokeniser.Token.START_ARRAY);
			Object[] row = new Object[headers.size()];
			for (int i = 0; i < headers.size(); ++i) {
				if (i != 0)
					json.consume(JSONTokeniser.Token.COMMA);
				row[i] = json.consume();
			}
			json.consume(JSONTokeniser.Token.END_ARRAY);
			int _id = JSONTokeniser.narrow(row[columnIndex__id], Integer.class);
			SubscriberId my_sid;
			try {
				my_sid = new SubscriberId(JSONTokeniser.narrow(row[columnIndex_my_sid], String.class));
			}
			catch (SubscriberId.InvalidHexException e) {
				throw new ServalDInterfaceException("invalid column value: my_sid", e);
			}
			SubscriberId their_sid;
			try {
				their_sid = new SubscriberId(JSONTokeniser.narrow(row[columnIndex_their_sid], String.class));
			}
			catch (SubscriberId.InvalidHexException e) {
				throw new ServalDInterfaceException("invalid column value: their_sid", e);
			}
			boolean is_read = JSONTokeniser.narrow(row[columnIndex_read], Boolean.class);
			int last_message = JSONTokeniser.narrow(row[columnIndex_last_message], Integer.class);
			int read_offset = JSONTokeniser.narrow(row[columnIndex_read_offset], Integer.class);
			return new MeshMSConversation(rowCount++, _id, my_sid, their_sid, is_read, last_message, read_offset);
		}
		catch (JSONInputException e) {
			throw new ServalDInterfaceException(e);
		}
	}

	public void close() throws IOException
	{
		httpConnection = null;
		if (json != null) {
			json.close();
			json = null;
		}
		headers = null;
	}

}
