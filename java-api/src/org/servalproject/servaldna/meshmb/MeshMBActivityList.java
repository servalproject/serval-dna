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

import org.servalproject.json.JSONTableScanner;
import org.servalproject.servaldna.AbstractJsonList;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SigningKey;
import org.servalproject.servaldna.Subscriber;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;
import java.util.Map;

public class MeshMBActivityList extends AbstractJsonList<MeshMBActivityMessage, IOException> {
	private final Subscriber identity;
	private final String token;

	public MeshMBActivityList(ServalDHttpConnectionFactory httpConnector, Subscriber identity, String token) {
		super(httpConnector, new JSONTableScanner()
				.addColumn(".token", String.class)
				.addColumn("ack_offset", Long.class)
				.addColumn("id", SigningKey.class)
				.addColumn("author", SubscriberId.class)
				.addColumn("name", String.class)
				.addColumn("timestamp", Long.class)
				.addColumn("offset", Long.class)
				.addColumn("message", String.class));
		this.identity = identity;
		this.token = token;
	}

	@Override
	protected String getUrl() {
		if (token == null)
			return "/restful/meshmb/" + identity.signingKey.toHex() + "/activity.json";
		if (token.equals(""))
			return "/restful/meshmb/" + identity.signingKey.toHex() + "/activity/activity.json";
		return "/restful/meshmb/" + identity.signingKey.toHex() + "/activity/"+token+"/activity.json";
	}

	@Override
	protected MeshMBActivityMessage factory(Map<String, Object> row, long rowCount) throws ServalDInterfaceException {
		return new MeshMBActivityMessage(
				(String) row.get(".token"),
				(Long) row.get("ack_offset"),
				new Subscriber((SubscriberId)row.get("author"),
						(SigningKey) row.get("id"),
						true),
				(String) row.get("name"),
				(Long) row.get("timestamp"),
				(Long) row.get("offset"),
				(String) row.get("message")
		);
	}
}
