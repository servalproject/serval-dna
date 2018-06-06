/**
 * Copyright (C) 2016 Flinders University
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

package org.servalproject.servaldna.keyring;

import org.servalproject.json.JsonObjectHelper;
import org.servalproject.json.JsonParser;
import org.servalproject.servaldna.HttpJsonSerialiser;
import org.servalproject.servaldna.HttpRequest;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SigningKey;
import org.servalproject.servaldna.Subscriber;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

public class KeyringIdentityList extends HttpJsonSerialiser<KeyringIdentity, IOException> {

	private final String pin;
	public KeyringIdentityList(ServalDHttpConnectionFactory connector, String pin)
	{
		super(connector);
		addField("sid", true, SubscriberId.class);
		addField("identity", true, SigningKey.class);
		addField("did", false, JsonObjectHelper.StringFactory);
		addField("name", false, JsonObjectHelper.StringFactory);
		this.pin = pin;
	}

	@Override
	protected HttpRequest getRequest() throws UnsupportedEncodingException {
		Vector<ServalDHttpConnectionFactory.QueryParam> query_params = new Vector<ServalDHttpConnectionFactory.QueryParam>();
		if (pin != null)
			query_params.add(new ServalDHttpConnectionFactory.QueryParam("pin", pin));
		return new HttpRequest("GET", "/restful/keyring/identities.json", query_params);
	}

	public static List<KeyringIdentity> getTestIdentities() {
		try {
			List<KeyringIdentity> ret = new ArrayList<KeyringIdentity>();
			byte[] sid = new byte[SubscriberId.BINARY_SIZE];

			for (int i = 0; i < 10; i++) {
				sid[0]=(byte)i;
				ret.add(new KeyringIdentity(
						i,
						new Subscriber(new SubscriberId(sid), new SigningKey(sid), true),
						"555000" + i,
						"Agent " + i));
			}
			return ret;
		}catch (Exception e){
			throw new IllegalStateException(e);
		}
	}

	@Override
	public KeyringIdentity create(Object[] parameters, int row) {
		return new KeyringIdentity(
				row,
				new Subscriber((SubscriberId)parameters[0],
						(SigningKey)parameters[1],
						true),
				(String)parameters[2],
				(String)parameters[3]);
	}

	@Deprecated
	public KeyringIdentity nextIdentity() throws IOException, ServalDInterfaceException {
		try {
			return next();
		} catch (JsonParser.JsonParseException e) {
			throw new ServalDInterfaceException(e);
		}
	}
}
