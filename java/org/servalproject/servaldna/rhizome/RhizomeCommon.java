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

package org.servalproject.servaldna.rhizome;

import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.json.JSONTokeniser;
import org.servalproject.json.JSONInputException;

public class RhizomeCommon
{
	protected static JSONTokeniser receiveRestfulResponse(HttpURLConnection conn, int expected_response_code) throws IOException, ServalDInterfaceException
	{
		int[] expected_response_codes = { expected_response_code };
		return receiveRestfulResponse(conn, expected_response_codes);
	}

	protected static JSONTokeniser receiveRestfulResponse(HttpURLConnection conn, int[] expected_response_codes) throws IOException, ServalDInterfaceException
	{
		if (!conn.getContentType().equals("application/json"))
			throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + conn.getContentType());
		if (conn.getResponseCode() == HttpURLConnection.HTTP_FORBIDDEN) {
			JSONTokeniser json = new JSONTokeniser(new InputStreamReader(conn.getErrorStream(), "US-ASCII"));
			Status status = decodeRestfulStatus(json);
			throw new ServalDInterfaceException("unexpected Rhizome failure, \"" + status.message + "\"");
		}
		for (int code: expected_response_codes) {
			if (conn.getResponseCode() == code) {
				JSONTokeniser json = new JSONTokeniser(new InputStreamReader(conn.getInputStream(), "US-ASCII"));
				return json;
			}
		}
		throw new ServalDInterfaceException("unexpected HTTP response code: " + conn.getResponseCode());
	}

	private static class Status {
		public String message;
	}

	protected static Status decodeRestfulStatus(JSONTokeniser json) throws IOException, ServalDInterfaceException
	{
		try {
			Status status = new Status();
			json.consume(JSONTokeniser.Token.START_OBJECT);
			json.consume("http_status_code");
			json.consume(JSONTokeniser.Token.COLON);
			json.consume(Integer.class);
			json.consume(JSONTokeniser.Token.COMMA);
			status.message = json.consume("http_status_message");
			json.consume(JSONTokeniser.Token.COLON);
			String message = json.consume(String.class);
			json.consume(JSONTokeniser.Token.END_OBJECT);
			json.consume(JSONTokeniser.Token.EOF);
			return status;
		}
		catch (JSONInputException e) {
			throw new ServalDInterfaceException("malformed JSON status response", e);
		}
	}

}
