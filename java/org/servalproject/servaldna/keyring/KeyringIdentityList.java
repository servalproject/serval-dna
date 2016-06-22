/**
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

import org.servalproject.json.JSONInputException;
import org.servalproject.json.JSONTableScanner;
import org.servalproject.json.JSONTokeniser;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import java.util.Map;

public class KeyringIdentityList {

	private ServalDHttpConnectionFactory httpConnector;
	private HttpURLConnection httpConnection;
	private JSONTokeniser json;
	private JSONTableScanner table;
	int rowCount;

	public KeyringIdentityList(ServalDHttpConnectionFactory connector)
	{
		this.httpConnector = connector;
		this.table = new JSONTableScanner()
					.addColumn("sid", SubscriberId.class)
					.addColumn("did", String.class, JSONTokeniser.Narrow.ALLOW_NULL)
					.addColumn("name", String.class, JSONTokeniser.Narrow.ALLOW_NULL);
	}

	public boolean isConnected()
	{
		return this.json != null;
	}

	public void connect(String pin) throws IOException, ServalDInterfaceException
	{
		try {
			rowCount = 0;
			Vector<ServalDHttpConnectionFactory.QueryParam> query_params = new Vector<ServalDHttpConnectionFactory.QueryParam>();
			if (pin != null) {
				query_params.add(new ServalDHttpConnectionFactory.QueryParam("pin", pin));
			}
			httpConnection = httpConnector.newServalDHttpConnection("/restful/keyring/identities.json", query_params);
			httpConnection.connect();
			KeyringCommon.Status status = KeyringCommon.receiveRestfulResponse(httpConnection, HttpURLConnection.HTTP_OK);
			json = status.json;
			json.consume(JSONTokeniser.Token.START_OBJECT);
			json.consume("header");
			json.consume(JSONTokeniser.Token.COLON);
			table.consumeHeaderArray(json);
			json.consume(JSONTokeniser.Token.COMMA);
			json.consume("rows");
			json.consume(JSONTokeniser.Token.COLON);
			json.consume(JSONTokeniser.Token.START_ARRAY);
		}
		catch (JSONInputException e) {
			throw new ServalDInterfaceException(e);
		}
	}

	public static List<KeyringIdentity> getTestIdentities() {
		try {
			List<KeyringIdentity> ret = new ArrayList<>();
			byte[] sid = new byte[SubscriberId.BINARY_SIZE];

			for (int i = 0; i < 10; i++) {
				sid[0]=(byte)i;
				ret.add(new KeyringIdentity(
						i,
						new SubscriberId(sid),
						"555000" + i,
						"Agent " + i));
			}
			return ret;
		}catch (Exception e){
			throw new IllegalStateException(e);
		}
	}

	public KeyringIdentity nextIdentity() throws ServalDInterfaceException, IOException
	{
		try {
			Object tok = json.nextToken();
			if (tok == JSONTokeniser.Token.END_ARRAY) {
				json.consume(JSONTokeniser.Token.END_OBJECT);
				json.consume(JSONTokeniser.Token.EOF);
				return null;
			}
			if (rowCount != 0)
				JSONTokeniser.match(tok, JSONTokeniser.Token.COMMA);
			else
				json.pushToken(tok);
			Map<String,Object> row = table.consumeRowArray(json);
			return new KeyringIdentity(
					rowCount++,
					(SubscriberId)row.get("sid"),
					(String)row.get("did"),
					(String)row.get("name")
				);
		}
		catch (JSONInputException e) {
			throw new ServalDInterfaceException(e);
		}
	}

	public void close() throws IOException
	{
		httpConnection = null;
		if (json != null) {
			json.close();
			json = null;
		}
	}

}
