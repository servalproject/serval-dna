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

import org.servalproject.json.JSONInputException;
import org.servalproject.json.JSONTableScanner;
import org.servalproject.json.JSONTokeniser;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.Subscriber;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class MeshMSMessageList {

	private ServalDHttpConnectionFactory httpConnector;
	private SubscriberId my_sid;
	private SubscriberId their_sid;
	private String sinceToken;
	private HttpURLConnection httpConnection;
	private JSONTokeniser json;
	private JSONTableScanner table;
	private long readOffset;
	private long latestAckOffset;
	private int rowCount;

	public MeshMSMessageList(ServalDHttpConnectionFactory connector, SubscriberId my_sid, SubscriberId their_sid)
	{
		this(connector, my_sid, their_sid, null);
	}

	public MeshMSMessageList(ServalDHttpConnectionFactory connector, SubscriberId my_sid, SubscriberId their_sid, String since_token)
	{
		this.httpConnector = connector;
		this.my_sid = my_sid;
		this.their_sid = their_sid;
		this.sinceToken = since_token;
		this.table = new JSONTableScanner()
					.addColumn("type", String.class)
					.addColumn("my_sid", SubscriberId.class)
					.addColumn("their_sid", SubscriberId.class)
					.addColumn("offset", Long.class)
					.addColumn("token", String.class)
					.addColumn("text", String.class, JSONTokeniser.Narrow.ALLOW_NULL)
					.addColumn("delivered", Boolean.class)
					.addColumn("read", Boolean.class)
					.addColumn("timestamp", Long.class, JSONTokeniser.Narrow.ALLOW_NULL)
					.addColumn("ack_offset", Long.class, JSONTokeniser.Narrow.ALLOW_NULL);
	}

	public boolean isConnected()
	{
		return this.json != null;
	}

	public void connect() throws MeshMSException, ServalDInterfaceException, IOException
	{
		assert json == null;
		try {
			rowCount = 0;
			if (this.sinceToken == null)
				httpConnection = httpConnector.newServalDHttpConnection("/restful/meshms/" + my_sid.toHex() + "/" + their_sid.toHex() + "/messagelist.json");
			else
				httpConnection = httpConnector.newServalDHttpConnection("/restful/meshms/" + my_sid.toHex() + "/" + their_sid.toHex() + "/newsince/" + sinceToken + "/messagelist.json");
			httpConnection.connect();
			json = MeshMSCommon.receiveRestfulResponse(httpConnection, HttpURLConnection.HTTP_OK);
			json.consume(JSONTokeniser.Token.START_OBJECT);
			if (this.sinceToken == null) {
				json.consume("read_offset");
				json.consume(JSONTokeniser.Token.COLON);
				readOffset = json.consume(Long.class);
				json.consume(JSONTokeniser.Token.COMMA);
				json.consume("latest_ack_offset");
				json.consume(JSONTokeniser.Token.COLON);
				latestAckOffset = json.consume(Long.class);
				json.consume(JSONTokeniser.Token.COMMA);
			}
			json.consume("header");
			json.consume(JSONTokeniser.Token.COLON);
			table.consumeHeaderArray(json);
			json.consume(JSONTokeniser.Token.COMMA);
			json.consume("rows");
			json.consume(JSONTokeniser.Token.COLON);
			json.consume(JSONTokeniser.Token.START_ARRAY);
		}
		catch (JSONInputException e) {
			throw new ServalDInterfaceException(e);
		}
	}

	public long getReadOffset()
	{
		assert json != null;
		return readOffset;
	}

	public long getLatestAckOffset()
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
			Map<String,Object> row = table.consumeRowArray(json);
			String typesym = (String) row.get("type");
			MeshMSMessage.Type type;
			if (typesym.equals(">"))
				type = MeshMSMessage.Type.MESSAGE_SENT;
			else if (typesym.equals("<"))
				type = MeshMSMessage.Type.MESSAGE_RECEIVED;
			else if (typesym.equals("ACK"))
				type = MeshMSMessage.Type.ACK_RECEIVED;
			else
				throw new ServalDInterfaceException("invalid column value: type=" + typesym);
			return new MeshMSMessage(
							rowCount++,
							type,
							new Subscriber((SubscriberId)row.get("my_sid")),
							new Subscriber((SubscriberId)row.get("their_sid")),
							(Long)row.get("offset"),
							(String)row.get("token"),
							(String)row.get("text"),
							(Boolean)row.get("delivered"),
							(Boolean)row.get("read"),
							(Long)row.get("timestamp"),
							(Long)row.get("ack_offset")
						);
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
	}

	public List<MeshMSMessage> toList() throws ServalDInterfaceException, IOException {
		List<MeshMSMessage> ret = new ArrayList<MeshMSMessage>();
		MeshMSMessage item;
		while ((item = nextMessage()) != null) {
			ret.add(item);
		}
		return ret;
	}
}
