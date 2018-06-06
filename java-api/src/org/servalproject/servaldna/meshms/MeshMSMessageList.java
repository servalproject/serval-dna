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

import org.servalproject.json.JsonObjectHelper;
import org.servalproject.json.JsonParser;
import org.servalproject.servaldna.HttpJsonSerialiser;
import org.servalproject.servaldna.HttpRequest;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.Subscriber;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;

public class MeshMSMessageList extends HttpJsonSerialiser<MeshMSMessage, ServalDInterfaceException> {

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
		super(connector);
		addField("type", true, JsonObjectHelper.StringFactory);
		addField("my_sid", true, SubscriberId.class);
		addField("their_sid", true, SubscriberId.class);
		addField("my_offset", true, JsonObjectHelper.LongFactory);
		addField("their_offset", true, JsonObjectHelper.LongFactory);
		addField("token", true, JsonObjectHelper.StringFactory);
		addField("text", false, JsonObjectHelper.StringFactory);
		addField("delivered", true, JsonObjectHelper.BoolFactory);
		addField("read", true, JsonObjectHelper.BoolFactory);
		addField("timestamp", false, JsonObjectHelper.LongFactory);
		addField("ack_offset", false, JsonObjectHelper.LongFactory);
		this.my_sid = my_sid;
		this.their_sid = their_sid;
		this.sinceToken = since_token;
	}

	@Override
	protected HttpRequest getRequest() {
		String suffix;
		if (this.sinceToken == null)
			suffix = "/messagelist.json";
		else if(this.sinceToken.equals(""))
			suffix = "/newsince/messagelist.json";
		else
			suffix = "/newsince/" + sinceToken + "/messagelist.json";

		return new MeshMSRequest("GET", "/restful/meshms/" + my_sid.toHex() + "/" + their_sid.toHex() + suffix){
			@Override
			public boolean checkResponse() throws IOException, ServalDInterfaceException {
				if (super.checkResponse())
					return true;
				decodeJson();
				return false;
			}
		};
	}

	@Override
	public void consumeObject(JsonParser.JsonMember header) throws IOException, JsonParser.JsonParseException {
		if (header.name.equals("read_offset") && header.type == JsonParser.ValueType.Number)
			readOffset = parser.readNumber().longValue();
		else if(header.name.equals("latest_ack_offset") && header.type == JsonParser.ValueType.Number)
			latestAckOffset = parser.readNumber().longValue();
		else
			super.consumeObject(header);
	}

	@Override
	public MeshMSMessage create(Object[] parameters, int row) throws ServalDInterfaceException{
		String typesym = (String)parameters[0];
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
				row,
				type,
				new Subscriber((SubscriberId)parameters[1]),
				new Subscriber((SubscriberId)parameters[2]),
				(Long)parameters[3],
				(Long)parameters[4],
				(String)parameters[5],
				(String)parameters[6],
				(Boolean)parameters[7],
				(Boolean)parameters[8],
				(Long)parameters[9],
				(Long)parameters[10]
		);
	}

	public long getReadOffset()
	{
		assert parser != null;
		return readOffset;
	}

	public long getLatestAckOffset()
	{
		assert parser != null;
		return latestAckOffset;
	}

	public MeshMSMessage nextMessage() throws ServalDInterfaceException, IOException {
		try {
			return next();
		} catch (JsonParser.JsonParseException e) {
			throw new ServalDInterfaceException(e);
		}
	}
}
