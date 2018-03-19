/**
 * Copyright (C) 2016 Flinders University
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

public class MeshMSConversationList {

	private ServalDHttpConnectionFactory httpConnector;
	private SubscriberId sid;
	private HttpURLConnection httpConnection;
	private JSONTokeniser json;
	private JSONTableScanner table;
	int rowCount;

	public MeshMSConversationList(ServalDHttpConnectionFactory connector, SubscriberId sid)
	{
		this.httpConnector = connector;
		this.sid = sid;
		this.table = new JSONTableScanner()
				.addColumn("_id", Integer.class)
				.addColumn("my_sid", SubscriberId.class)
				.addColumn("their_sid", SubscriberId.class)
				.addColumn("read", Boolean.class)
				.addColumn("last_message", Long.class)
				.addColumn("read_offset", Long.class)
		;
	}

	public boolean isConnected()
	{
		return this.json != null;
	}

	public void connect() throws IOException, ServalDInterfaceException, MeshMSException
	{
		try {
			rowCount = 0;
			httpConnection = httpConnector.newServalDHttpConnection("GET", "/restful/meshms/" + sid.toHex() + "/conversationlist.json");
			httpConnection.connect();
			json = MeshMSCommon.receiveRestfulResponse(httpConnection, HttpURLConnection.HTTP_OK);
			json.consume(JSONTokeniser.Token.START_OBJECT);
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

	public MeshMSConversation nextConversation() throws ServalDInterfaceException, IOException
	{
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

			return new MeshMSConversation(
					rowCount++,
					(Integer)row.get("_id"),
					new Subscriber((SubscriberId)row.get("my_sid")),
					new Subscriber((SubscriberId)row.get("their_sid")),
					(Boolean)row.get("read"),
					(Long)row.get("last_message"),
					(Long)row.get("read_offset"));
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

	public List<MeshMSConversation> toList() throws ServalDInterfaceException, IOException {
		List<MeshMSConversation> ret = new ArrayList<MeshMSConversation>();
		MeshMSConversation item;
		while ((item = nextConversation()) != null) {
			ret.add(item);
		}
		return ret;
	}
}
