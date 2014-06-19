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
import java.util.Vector;
import java.net.HttpURLConnection;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SubscriberId;
import org.servalproject.json.JSONTokeniser;
import org.servalproject.json.JSONInputException;

public class MeshMSMessageList {

	private ServalDHttpConnectionFactory httpConnector;
	private SubscriberId my_sid;
	private SubscriberId their_sid;
	private HttpURLConnection httpConnection;
	private JSONTokeniser json;
	private int	readOffset;
	private int	latestAckOffset;
	private Vector<String> headers;
	private int columnIndex_type;
	private int columnIndex_my_sid;
	private int columnIndex_their_sid;
	private int columnIndex_offset;
	private int columnIndex_token;
	private int columnIndex_text;
	private int columnIndex_delivered;
	private int columnIndex_read;
	private int columnIndex_ack_offset;
	private int rowCount;

	public MeshMSMessageList(ServalDHttpConnectionFactory connector, SubscriberId my_sid, SubscriberId their_sid)
	{
		this.httpConnector = connector;
		this.my_sid = my_sid;
		this.their_sid = their_sid;
	}

	public boolean isConnected()
	{
		return this.json != null;
	}

	public void connect() throws MeshMSException, ServalDInterfaceException, IOException
	{
		assert json == null;
		try {
			columnIndex_type = -1;
			columnIndex_my_sid = -1;
			columnIndex_their_sid = -1;
			columnIndex_offset = -1;
			columnIndex_token = -1;
			columnIndex_text = -1;
			columnIndex_delivered = -1;
			columnIndex_read = -1;
			columnIndex_ack_offset = -1;
			rowCount = 0;
			httpConnection = httpConnector.newServalDHttpConnection("/restful/meshms/" + my_sid.toHex() + "/" + their_sid.toHex() + "/messagelist.json");
			json = MeshMSCommon.connectMeshMSRestful(httpConnection);
			json.consume(JSONTokeniser.Token.START_OBJECT);
			json.consume("read_offset");
			json.consume(JSONTokeniser.Token.COLON);
			readOffset = json.consume(Integer.class);
			json.consume(JSONTokeniser.Token.COMMA);
			json.consume("latest_ack_offset");
			json.consume(JSONTokeniser.Token.COLON);
			latestAckOffset = json.consume(Integer.class);
			json.consume(JSONTokeniser.Token.COMMA);
			json.consume("header");
			json.consume(JSONTokeniser.Token.COLON);
			headers = new Vector<String>();
			json.consumeArray(headers, String.class);
			if (headers.size() < 1)
				throw new ServalDInterfaceException("empty JSON headers array");
			for (int i = 0; i < headers.size(); ++i) {
				String header = headers.get(i);
				if (header.equals("type"))
					columnIndex_type = i;
				else if (header.equals("my_sid"))
					columnIndex_my_sid = i;
				else if (header.equals("their_sid"))
					columnIndex_their_sid = i;
				else if (header.equals("offset"))
					columnIndex_offset = i;
				else if (header.equals("token"))
					columnIndex_token = i;
				else if (header.equals("text"))
					columnIndex_text = i;
				else if (header.equals("delivered"))
					columnIndex_delivered = i;
				else if (header.equals("read"))
					columnIndex_read = i;
				else if (header.equals("ack_offset"))
					columnIndex_ack_offset = i;
			}
			if (columnIndex_type == -1)
				throw new ServalDInterfaceException("missing JSON column: type");
			if (columnIndex_my_sid == -1)
				throw new ServalDInterfaceException("missing JSON column: my_sid");
			if (columnIndex_their_sid == -1)
				throw new ServalDInterfaceException("missing JSON column: their_sid");
			if (columnIndex_offset == -1)
				throw new ServalDInterfaceException("missing JSON column: offset");
			if (columnIndex_token == -1)
				throw new ServalDInterfaceException("missing JSON column: token");
			if (columnIndex_text == -1)
				throw new ServalDInterfaceException("missing JSON column: text");
			if (columnIndex_delivered == -1)
				throw new ServalDInterfaceException("missing JSON column: delivered");
			if (columnIndex_read == -1)
				throw new ServalDInterfaceException("missing JSON column: read");
			if (columnIndex_ack_offset == -1)
				throw new ServalDInterfaceException("missing JSON column: ack_offset");
			json.consume(JSONTokeniser.Token.COMMA);
			json.consume("rows");
			json.consume(JSONTokeniser.Token.COLON);
			json.consume(JSONTokeniser.Token.START_ARRAY);
		}
		catch (JSONInputException e) {
			throw new ServalDInterfaceException(e);
		}
	}

	public int getReadOffset()
	{
		assert json != null;
		return readOffset;
	}

	public int getLatestAckOffset()
	{
		assert json != null;
		return latestAckOffset;
	}

	public MeshMSMessage nextMessage() throws ServalDInterfaceException, IOException
	{
		assert json != null;
		try {
			Object tok = json.nextToken();
			if (tok == JSONTokeniser.Token.END_ARRAY) {
				json.consume(JSONTokeniser.Token.END_OBJECT);
				json.consume(JSONTokeniser.Token.EOF);
				return null;
			}
			if (rowCount != 0)
				JSONTokeniser.match(tok, JSONTokeniser.Token.COMMA);
			else
				json.pushToken(tok);
			Object[] row = new Object[headers.size()];
			json.consumeArray(row, JSONTokeniser.Narrow.ALLOW_NULL);
			String typesym = JSONTokeniser.narrow(row[columnIndex_type], String.class);
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
			int offset = JSONTokeniser.narrow(row[columnIndex_offset], Integer.class);
			String token = JSONTokeniser.narrow(row[columnIndex_token], String.class);
			String text = JSONTokeniser.narrow(row[columnIndex_text], String.class, JSONTokeniser.Narrow.ALLOW_NULL);
			boolean is_delivered = JSONTokeniser.narrow(row[columnIndex_delivered], Boolean.class);
			boolean is_read = JSONTokeniser.narrow(row[columnIndex_read], Boolean.class);
			Integer ack_offset = JSONTokeniser.narrow(row[columnIndex_ack_offset], Integer.class, JSONTokeniser.Narrow.ALLOW_NULL);
			MeshMSMessage.Type type;
			if (typesym.equals(">"))
				type = MeshMSMessage.Type.MESSAGE_SENT;
			else if (typesym.equals("<"))
				type = MeshMSMessage.Type.MESSAGE_RECEIVED;
			else if (typesym.equals("ACK"))
				type = MeshMSMessage.Type.ACK_RECEIVED;
			else
				throw new ServalDInterfaceException("invalid column value: type=" + typesym);
			return new MeshMSMessage(rowCount++, type, my_sid, their_sid, offset, token, text, is_delivered, is_read, ack_offset);
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
