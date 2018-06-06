/**
 * Copyright (C) 2016-2017 Flinders University
 * Copyright (C) 2015 Serval Project Inc.
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

import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.Vector;

public class KeyringCommon
{

	protected static ServalDInterfaceException unexpectedResponse(KeyringRequest request)
	{
		return new ServalDInterfaceException(
				"unexpected Keyring failure, " + quoteString(request.httpStatusMessage)
				+ " from " + request.url
			);
	}

	private static String quoteString(String unquoted)
	{
		if (unquoted == null)
			return "null";
		StringBuilder b = new StringBuilder(unquoted.length() + 2);
		b.append('"');
		for (int i = 0; i < unquoted.length(); ++i) {
			char c = unquoted.charAt(i);
			if (c == '"' || c == '\\')
				b.append('\\');
			b.append(c);
		}
		b.append('"');
		return b.toString();
	}

	public static KeyringIdentity setDidName(ServalDHttpConnectionFactory connector, SubscriberId sid, String did, String name, String pin)
		throws IOException, ServalDInterfaceException
	{
		Vector<ServalDHttpConnectionFactory.QueryParam> query_params = new Vector<ServalDHttpConnectionFactory.QueryParam>();
		if (did != null)
			query_params.add(new ServalDHttpConnectionFactory.QueryParam("did", did));
		if (name != null)
			query_params.add(new ServalDHttpConnectionFactory.QueryParam("name", name));
		if (pin != null)
			query_params.add(new ServalDHttpConnectionFactory.QueryParam("pin", pin));
		KeyringRequest request = new KeyringRequest("POST", "/restful/keyring/" + sid.toHex(), query_params);
		try {
			request.connect(connector);
			if (request.identity == null)
				throw new ServalDInterfaceException("invalid JSON response; missing identity");

			return request.identity;
		}
		finally {
			request.close();
		}
	}

	public static KeyringIdentity addIdentity(ServalDHttpConnectionFactory connector, String did, String name, String pin)
		throws IOException, ServalDInterfaceException
	{
		Vector<ServalDHttpConnectionFactory.QueryParam> query_params = new Vector<ServalDHttpConnectionFactory.QueryParam>();
		if (did != null)
			query_params.add(new ServalDHttpConnectionFactory.QueryParam("did", did));
		if (name != null)
			query_params.add(new ServalDHttpConnectionFactory.QueryParam("name", name));
		if (pin != null)
			query_params.add(new ServalDHttpConnectionFactory.QueryParam("pin", pin));
		KeyringRequest request = new KeyringRequest("POST", "/restful/keyring/add", query_params);
		try{
			request.setExpectedStatusCodes(HttpURLConnection.HTTP_CREATED);
			request.connect(connector);
			if (request.identity == null)
				throw new ServalDInterfaceException("invalid JSON response; missing identity");
			return request.identity;
		}
		finally {
			request.close();
		}
	}

	public static KeyringIdentity getIdentity(ServalDHttpConnectionFactory connector, SubscriberId sid, String pin)
		throws IOException, ServalDInterfaceException
	{
		Vector<ServalDHttpConnectionFactory.QueryParam> query_params = new Vector<ServalDHttpConnectionFactory.QueryParam>();
		if (pin != null)
			query_params.add(new ServalDHttpConnectionFactory.QueryParam("pin", pin));
		KeyringRequest request = new KeyringRequest("GET", "/restful/keyring/" + sid.toHex(), query_params);
		try {
			request.connect(connector);
			if (request.identity == null)
				throw new ServalDInterfaceException("invalid JSON response; missing identity");
			return request.identity;
		}
		finally {
			request.close();
		}
	}

	public static KeyringIdentity removeIdentity(ServalDHttpConnectionFactory connector, SubscriberId sid, String pin)
		throws IOException, ServalDInterfaceException
	{
		Vector<ServalDHttpConnectionFactory.QueryParam> query_params = new Vector<ServalDHttpConnectionFactory.QueryParam>();
		if (pin != null)
			query_params.add(new ServalDHttpConnectionFactory.QueryParam("pin", pin));
		KeyringRequest request = new KeyringRequest("DELETE", "/restful/keyring/" + sid.toHex(), query_params);

		try {
			request.connect(connector);
			if (request.identity == null)
				throw new ServalDInterfaceException("invalid JSON response; missing identity");
			return request.identity;
		}
		finally {
			request.close();
		}
	}

}
