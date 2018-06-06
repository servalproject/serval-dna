/**
 * Copyright (C) 2017 Flinders University
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

package org.servalproject.servaldna.meshmb;

import org.servalproject.json.JsonObjectHelper;
import org.servalproject.servaldna.HttpJsonSerialiser;
import org.servalproject.servaldna.HttpRequest;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.SigningKey;
import org.servalproject.servaldna.Subscriber;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;

public class MeshMBActivityList extends HttpJsonSerialiser<MeshMBActivityMessage, IOException> {
	private final Subscriber identity;
	private final String token;

	public MeshMBActivityList(ServalDHttpConnectionFactory httpConnector, Subscriber identity, String token) {
		super(httpConnector);
		addField(".token", true, JsonObjectHelper.StringFactory);
		addField("ack_offset", true, JsonObjectHelper.LongFactory);
		addField("id", true, SigningKey.class);
		addField("author", true, SubscriberId.class);
		addField("name", false, JsonObjectHelper.StringFactory);
		addField("timestamp", true, JsonObjectHelper.LongFactory);
		addField("offset", true, JsonObjectHelper.LongFactory);
		addField("message", true, JsonObjectHelper.StringFactory);
		this.identity = identity;
		this.token = token;
	}

	@Override
	protected HttpRequest getRequest() {
		if (token == null)
			return new HttpRequest("GET", "/restful/meshmb/" + identity.signingKey.toHex() + "/activity.json");
		if (token.equals(""))
			return new HttpRequest("GET", "/restful/meshmb/" + identity.signingKey.toHex() + "/activity/activity.json");
		return new HttpRequest("GET", "/restful/meshmb/" + identity.signingKey.toHex() + "/activity/"+token+"/activity.json");
	}

	@Override
	public MeshMBActivityMessage create(Object[] parameters, int row) {
		return new MeshMBActivityMessage(
				(String) parameters[0],
				(Long) parameters[1],
				new Subscriber((SubscriberId)parameters[2],
						(SigningKey) parameters[3],
						true),
				(String) parameters[4],
				(Long) parameters[5],
				(Long) parameters[6],
				(String) parameters[7]
		);
	}
}
