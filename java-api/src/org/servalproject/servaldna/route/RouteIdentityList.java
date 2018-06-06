/**
 * Copyright (C) 2016-2018 Flinders University
 * Copyright (C) 2014-2015 Serval Project Inc.
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

package org.servalproject.servaldna.route;

import org.servalproject.json.JsonObjectHelper;
import org.servalproject.servaldna.HttpJsonSerialiser;
import org.servalproject.servaldna.HttpRequest;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

public class RouteIdentityList extends HttpJsonSerialiser<RouteIdentity, IOException> {

	public RouteIdentityList(ServalDHttpConnectionFactory connector)
	{
		super(connector);
		addField("sid", true, SubscriberId.class);
		addField("did", false, JsonObjectHelper.StringFactory);
		addField("name", false, JsonObjectHelper.StringFactory);
		addField("is_self", true, JsonObjectHelper.BoolFactory);
		addField("hop_count", true, JsonObjectHelper.IntFactory);
		addField("reachable_broadcast", true, JsonObjectHelper.BoolFactory);
		addField("reachable_unicast", true, JsonObjectHelper.BoolFactory);
		addField("reachable_indirect", true, JsonObjectHelper.BoolFactory);
	}

	@Override
	protected HttpRequest getRequest() throws UnsupportedEncodingException {
		return new HttpRequest("GET", "/restful/route/all.json");
	}

	public static List<RouteIdentity> getTestIdentities() {
		try {
			List<RouteIdentity> ret = new ArrayList<RouteIdentity>();
			byte[] sid = new byte[SubscriberId.BINARY_SIZE];

			for (int i = 0; i < 10; i++) {
				sid[0]=(byte)i;
				ret.add(new RouteIdentity(i, new SubscriberId(sid), "555000" + i, "Agent " + i, i < 5, i, i >= 5, i >= 6, i >= 7));
			}
			return ret;
		}catch (Exception e){
			throw new IllegalStateException(e);
		}
	}

	@Override
	public RouteIdentity create(Object[] parameters, int row) {
		return new RouteIdentity(
				rowCount++,
				(SubscriberId)parameters[0],
				(String)parameters[1],
				(String)parameters[2],
				(Boolean)parameters[3],
				(Integer)parameters[4],
				(Boolean)parameters[5],
				(Boolean)parameters[6],
				(Boolean)parameters[7]
		);
	}
}
