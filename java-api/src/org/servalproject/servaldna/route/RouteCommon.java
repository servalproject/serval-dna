/**
 * Copyright (C) 2016-2018 Flinders University
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

package org.servalproject.servaldna.route;

import org.servalproject.json.JSONInputException;
import org.servalproject.json.JSONTokeniser;
import org.servalproject.servaldna.ContentType;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.ServalDNotImplementedException;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;

public class RouteCommon
{

	public static class Status {
		ContentType contentType;
		InputStream input_stream;
		JSONTokeniser json;
		public int http_status_code;
		public String http_status_message;
	}

	protected static Status receiveResponse(HttpURLConnection conn, int expected_response_code) throws IOException, ServalDInterfaceException
	{
		int[] expected_response_codes = { expected_response_code };
		return receiveResponse(conn, expected_response_codes);
	}

	protected static Status receiveResponse(HttpURLConnection conn, int[] expected_response_codes) throws IOException, ServalDInterfaceException
	{
		Status status = new Status();
		status.http_status_code = conn.getResponseCode();
		status.http_status_message = conn.getResponseMessage();
		try {
			status.contentType = new ContentType(conn.getContentType());
		} catch (ContentType.ContentTypeException e) {
			throw new ServalDInterfaceException("malformed HTTP Content-Type: " + conn.getContentType(),e);
		}

		for (int code: expected_response_codes) {
			if (status.http_status_code == code) {
				status.input_stream = conn.getInputStream();
				return status;
			}
		}
		if (!ContentType.applicationJson.matches(status.contentType))
			throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + status.contentType);
		if (status.http_status_code >= 300) {
			status.json = new JSONTokeniser(conn.getErrorStream());
			decodeRestfulStatus(status);
		}
		if (status.http_status_code == HttpURLConnection.HTTP_FORBIDDEN)
			return status;
		if (status.http_status_code == HttpURLConnection.HTTP_NOT_IMPLEMENTED)
			throw new ServalDNotImplementedException(status.http_status_message);
		throw new ServalDInterfaceException("unexpected HTTP response: " + status.http_status_code + " " + status.http_status_message);
	}

	protected static ServalDInterfaceException unexpectedResponse(HttpURLConnection conn, Status status)
	{
		return new ServalDInterfaceException(
				"unexpected Route failure, " + quoteString(status.http_status_message)
				+ " from " + conn.getURL()
			);
	}

	protected static Status receiveRestfulResponse(HttpURLConnection conn, int expected_response_code) throws IOException, ServalDInterfaceException
	{
		int[] expected_response_codes = { expected_response_code };
		return receiveRestfulResponse(conn, expected_response_codes);
	}

	protected static Status receiveRestfulResponse(HttpURLConnection conn, int[] expected_response_codes) throws IOException, ServalDInterfaceException
	{
		Status status = receiveResponse(conn, expected_response_codes);
		status.json = new JSONTokeniser(status.input_stream);
		return status;
	}

	protected static void decodeRestfulStatus(Status status) throws IOException, ServalDInterfaceException
	{
		JSONTokeniser json = status.json;
		try {
			json.consume(JSONTokeniser.Token.START_OBJECT);
			json.consume("http_status_code");
			json.consume(JSONTokeniser.Token.COLON);
			int hs = json.consume(Integer.class);
			json.consume(JSONTokeniser.Token.COMMA);
			if (status.http_status_code == 0)
				status.http_status_code = json.consume(Integer.class);
			else if (hs != status.http_status_code)
				throw new ServalDInterfaceException("JSON/header conflict"
						+ ", http_status_code=" + hs
						+ " but HTTP response code is " + status.http_status_code);
			json.consume("http_status_message");
			json.consume(JSONTokeniser.Token.COLON);
			status.http_status_message = json.consume(String.class);
			json.consume(JSONTokeniser.Token.END_OBJECT);
			json.consume(JSONTokeniser.Token.EOF);
		}
		catch (JSONInputException e) {
			throw new ServalDInterfaceException("malformed JSON status response", e);
		}
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

}

