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
import org.servalproject.servaldna.AbstractJsonList;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.Subscriber;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;
import java.util.Map;

public class MeshMSMessageList extends AbstractJsonList<MeshMSMessage, MeshMSException> {

	private final SubscriberId my_sid;
	private final SubscriberId their_sid;
	private final String sinceToken;
	private long readOffset;
	private long latestAckOffset;

	public MeshMSMessageList(ServalDHttpConnectionFactory connector, SubscriberId my_sid, SubscriberId their_sid)
	{
		this(connector, my_sid, their_sid, null);
	}

	public MeshMSMessageList(ServalDHttpConnectionFactory connector, SubscriberId my_sid, SubscriberId their_sid, String since_token)
	{
		super(connector, new JSONTableScanner()
				.addColumn("type", String.class)
				.addColumn("my_sid", SubscriberId.class)
				.addColumn("their_sid", SubscriberId.class)
				.addColumn("my_offset", Long.class)
				.addColumn("their_offset", Long.class)
				.addColumn("token", String.class)
				.addColumn("text", String.class, JSONTokeniser.Narrow.ALLOW_NULL)
				.addColumn("delivered", Boolean.class)
				.addColumn("read", Boolean.class)
				.addColumn("timestamp", Long.class, JSONTokeniser.Narrow.ALLOW_NULL)
				.addColumn("ack_offset", Long.class, JSONTokeniser.Narrow.ALLOW_NULL));
		this.my_sid = my_sid;
		this.their_sid = their_sid;
		this.sinceToken = since_token;
	}

	@Override
	protected String getUrl() {
		if (this.sinceToken == null)
			return "/restful/meshms/" + my_sid.toHex() + "/" + their_sid.toHex() + "/messagelist.json";
		else if(this.sinceToken.equals(""))
			return "/restful/meshms/" + my_sid.toHex() + "/" + their_sid.toHex() + "/newsince/messagelist.json";
		else
			return "/restful/meshms/" + my_sid.toHex() + "/" + their_sid.toHex() + "/newsince/" + sinceToken + "/messagelist.json";
	}

	@Override
	protected void consumeHeader() throws JSONInputException, IOException {
		Object tok = json.nextToken();
		if (tok.equals("read_offset")) {
			json.consume(JSONTokeniser.Token.COLON);
			readOffset = json.consume(Long.class);
			json.consume(JSONTokeniser.Token.COMMA);
		} else if (tok.equals("latest_ack_offset")) {
			json.consume(JSONTokeniser.Token.COLON);
			latestAckOffset = json.consume(Long.class);
			json.consume(JSONTokeniser.Token.COMMA);
		} else
			super.consumeHeader();
	}

	@Override
	protected void handleResponseError() throws MeshMSException, IOException, ServalDInterfaceException {
		if (json!=null)
			MeshMSCommon.processRestfulError(httpConnection, json);

		super.handleResponseError();
	}

	@Override
	protected MeshMSMessage factory(Map<String, Object> row, long rowCount) throws ServalDInterfaceException {
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
				(int)rowCount,
				type,
				new Subscriber((SubscriberId)row.get("my_sid")),
				new Subscriber((SubscriberId)row.get("their_sid")),
				(Long)row.get("my_offset"),
				(Long)row.get("their_offset"),
				(String)row.get("token"),
				(String)row.get("text"),
				(Boolean)row.get("delivered"),
				(Boolean)row.get("read"),
				(Long)row.get("timestamp"),
				(Long)row.get("ack_offset")
		);
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

	@Deprecated
	public MeshMSMessage nextMessage() throws ServalDInterfaceException, IOException
	{
		return next();
	}
}
