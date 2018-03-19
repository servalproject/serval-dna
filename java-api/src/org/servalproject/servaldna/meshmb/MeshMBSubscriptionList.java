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
import org.servalproject.json.JSONTokeniser;
import org.servalproject.servaldna.AbstractJsonList;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SigningKey;
import org.servalproject.servaldna.Subscriber;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;
import java.util.Map;

public class MeshMBSubscriptionList extends AbstractJsonList<MeshMBSubscription, IOException> {

	public final Subscriber identity;

	public MeshMBSubscriptionList(ServalDHttpConnectionFactory httpConnector, Subscriber identity){
		super(httpConnector, new JSONTableScanner()
				.addColumn("id", SigningKey.class)
				.addColumn("author", SubscriberId.class)
				.addColumn("blocked", Boolean.class)
				.addColumn("name", String.class, JSONTokeniser.Narrow.ALLOW_NULL)
				.addColumn("timestamp", Long.class)
				.addColumn("last_message", String.class, JSONTokeniser.Narrow.ALLOW_NULL)
		);
		this.identity = identity;
	}

	@Override
	protected Request getRequest() {
		return new Request("GET", "/restful/meshmb/" + identity.signingKey.toHex() + "/feedlist.json");
	}

	@Override
	protected MeshMBSubscription factory(Map<String, Object> row, long rowCount) throws ServalDInterfaceException {
		return new MeshMBSubscription(
				new Subscriber((SubscriberId)row.get("author"),
						(SigningKey) row.get("id"),
						true),
				(Boolean) row.get("blocked"),
				(String) row.get("name"),
				(Long) row.get("timestamp"),
				(String) row.get("last_message")
		);
	}
}
