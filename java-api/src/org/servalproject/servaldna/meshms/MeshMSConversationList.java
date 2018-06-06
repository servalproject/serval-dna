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

public class MeshMSConversationList extends HttpJsonSerialiser<MeshMSConversation,MeshMSException>{

	private SubscriberId sid;

	public MeshMSConversationList(ServalDHttpConnectionFactory connector, SubscriberId sid)
	{
		super(connector);
		this.sid = sid;
		addField("_id", true, JsonObjectHelper.IntFactory);
		addField("my_sid", true, SubscriberId.class);
		addField("their_sid", true, SubscriberId.class);
		addField("read", true, JsonObjectHelper.BoolFactory);
		addField("last_message", true, JsonObjectHelper.LongFactory);
		addField("read_offset", true, JsonObjectHelper.LongFactory);
	}

	@Override
	protected HttpRequest getRequest() {
		return new MeshMSRequest("GET", "/restful/meshms/" + sid.toHex() + "/conversationlist.json"){
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
	public MeshMSConversation create(Object[] parameters, int row) {
		return new MeshMSConversation(
				row,
				(Integer)parameters[0],
				new Subscriber((SubscriberId)parameters[1]),
				new Subscriber((SubscriberId)parameters[2]),
				(Boolean)parameters[3],
				(Long)parameters[4],
				(Long)parameters[5]);
	}

	@Deprecated
	public MeshMSConversation nextConversation() throws ServalDInterfaceException, IOException {
		try {
			return next();
		} catch (JsonParser.JsonParseException e) {
			throw new ServalDInterfaceException(e);
		}
	}
}
