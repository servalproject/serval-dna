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

public class MeshMBSubscriptionList extends HttpJsonSerialiser<MeshMBSubscription, IOException> {

	public final Subscriber identity;

	public MeshMBSubscriptionList(ServalDHttpConnectionFactory httpConnector, Subscriber identity){
		super(httpConnector);
		addField("id", true, SigningKey.class);
		addField("author", true, SubscriberId.class);
		addField("blocked", true, JsonObjectHelper.BoolFactory);
		addField("name", false, JsonObjectHelper.StringFactory);
		addField("timestamp", true, JsonObjectHelper.LongFactory);
		addField("last_message", false, JsonObjectHelper.StringFactory);
		this.identity = identity;
	}

	@Override
	protected HttpRequest getRequest() {
		return new HttpRequest("GET", "/restful/meshmb/" + identity.signingKey.toHex() + "/feedlist.json");
	}

	@Override
	public MeshMBSubscription create(Object[] parameters, int row) {
		return new MeshMBSubscription(
				new Subscriber((SubscriberId)parameters[0],
						(SigningKey)parameters[1],
						true),
				(Boolean) parameters[2],
				(String) parameters[3],
				(Long) parameters[4],
				(String) parameters[5]
		);
	}
}
