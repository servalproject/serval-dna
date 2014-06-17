/**
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

import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.json.JSONTokeniser;
import org.servalproject.json.JSONInputException;

class MeshMSCommon
{
	protected static JSONTokeniser connectMeshMSRestful(HttpURLConnection conn) throws IOException, ServalDInterfaceException, MeshMSException
	{
		conn.connect();
		if (!conn.getContentType().equals("application/json"))
			throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + conn.getContentType());
		if (conn.getResponseCode() == HttpURLConnection.HTTP_FORBIDDEN) {
			JSONTokeniser json = new JSONTokeniser(new InputStreamReader(conn.getErrorStream(), "US-ASCII"));
			try {
				json.consume(JSONTokeniser.Token.START_OBJECT);
				json.consume("http_status_code");
				json.consume(JSONTokeniser.Token.COLON);
				json.consume(Integer.class);
				json.consume(JSONTokeniser.Token.COMMA);
				json.consume("http_status_message");
				json.consume(JSONTokeniser.Token.COLON);
				String message = json.consume(String.class);
				json.consume(JSONTokeniser.Token.COMMA);
				json.consume("meshms_status_code");
				json.consume(JSONTokeniser.Token.COLON);
				int meshms_status = json.consume(Integer.class);
				json.consume(JSONTokeniser.Token.END_OBJECT);
				json.consume(JSONTokeniser.Token.EOF);
				switch (meshms_status) {
				case 2:
					throw new MeshMSUnknownIdentityException(conn.getURL());
				case 3:
					throw new MeshMSProtocolFaultException(conn.getURL());
				}
				throw new ServalDInterfaceException("unexpected MeshMS status = " + meshms_status + ", \"" + message + "\"");
			}
			catch (JSONInputException e) {
				throw new ServalDInterfaceException("malformed response body for HTTP status code " + conn.getResponseCode(), e);
			}
		}
		if (conn.getResponseCode() != HttpURLConnection.HTTP_OK)
			throw new ServalDInterfaceException("unexpected HTTP response code: " + conn.getResponseCode());
		JSONTokeniser json = new JSONTokeniser(new InputStreamReader(conn.getInputStream(), "US-ASCII"));
		return json;
	}

}
