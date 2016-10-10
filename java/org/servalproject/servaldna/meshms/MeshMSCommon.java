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

import org.servalproject.json.JSONInputException;
import org.servalproject.json.JSONTokeniser;
import org.servalproject.servaldna.PostHelper;
import org.servalproject.servaldna.ServalDFailureException;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

public class MeshMSCommon
{
	protected static JSONTokeniser receiveRestfulResponse(HttpURLConnection conn, int expected_response_code) throws IOException, ServalDInterfaceException, MeshMSException
	{
		int[] expected_response_codes = { expected_response_code };
		return receiveRestfulResponse(conn, expected_response_codes);
	}

	protected static JSONTokeniser receiveRestfulResponse(HttpURLConnection conn, int[] expected_response_codes) throws IOException, ServalDInterfaceException, MeshMSException
	{
		if (!"application/json".equals(conn.getContentType()))
			throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + conn.getContentType());
		for (int code: expected_response_codes) {
			if (conn.getResponseCode() == code) {
				JSONTokeniser json = new JSONTokeniser(conn.getInputStream());
				return json;
			}
		}
		switch (conn.getResponseCode()) {
		case HttpURLConnection.HTTP_NOT_FOUND:
		case 419: // Authentication Timeout, for missing secret
			JSONTokeniser json = new JSONTokeniser(conn.getErrorStream());
			Status status = decodeRestfulStatus(json);
			throwRestfulResponseExceptions(status, conn.getURL());
			throw new ServalDInterfaceException("unexpected MeshMS status = " + status.meshms_status_code + ", \"" + status.meshms_status_message + "\"");
		}
		throw new ServalDInterfaceException("unexpected HTTP response code: " + conn.getResponseCode());
	}

	private static class Status {
		public int http_status_code;
		public String http_status_message;
		public MeshMSStatus meshms_status_code;
		public String meshms_status_message;
	}

	protected static Status decodeRestfulStatus(JSONTokeniser json) throws IOException, ServalDInterfaceException
	{
		try {
			Status status = new Status();
			json.consume(JSONTokeniser.Token.START_OBJECT);
			json.consume("http_status_code");
			json.consume(JSONTokeniser.Token.COLON);
			status.http_status_code = json.consume(Integer.class);
			json.consume(JSONTokeniser.Token.COMMA);
			json.consume("http_status_message");
			json.consume(JSONTokeniser.Token.COLON);
			status.http_status_message = json.consume(String.class);
			Object tok = json.nextToken();
			if (tok == JSONTokeniser.Token.COMMA) {
				json.consume("meshms_status_code");
				json.consume(JSONTokeniser.Token.COLON);
				status.meshms_status_code = MeshMSStatus.fromCode(json.consume(Integer.class));
				json.consume(JSONTokeniser.Token.COMMA);
				json.consume("meshms_status_message");
				json.consume(JSONTokeniser.Token.COLON);
				status.meshms_status_message = json.consume(String.class);
				tok = json.nextToken();
			}
			json.match(tok, JSONTokeniser.Token.END_OBJECT);
			json.consume(JSONTokeniser.Token.EOF);
			return status;
		}
		catch (JSONInputException e) {
			throw new ServalDInterfaceException("malformed JSON status response", e);
		}
	}

	protected static void throwRestfulResponseExceptions(Status status, URL url) throws MeshMSException, ServalDFailureException
	{
		if (status.meshms_status_code == null) {
			throw new ServalDFailureException("missing meshms_status_code from " + url);
		}
		switch (status.meshms_status_code) {
		case OK:
		case UPDATED:
			break;
		case SID_LOCKED:
			throw new MeshMSUnknownIdentityException(url);
		case PROTOCOL_FAULT:
			throw new MeshMSProtocolFaultException(url);
		case ERROR:
			throw new ServalDFailureException("received meshms_status_code=ERROR(-1) from " + url);
		}
	}

	public static void processRestfulError(HttpURLConnection conn, JSONTokeniser json) throws IOException, ServalDInterfaceException, MeshMSException {
		switch (conn.getResponseCode()) {
			case HttpURLConnection.HTTP_NOT_FOUND:
			case 419: // Authentication Timeout, for missing secret
				Status status = decodeRestfulStatus(json);
				throwRestfulResponseExceptions(status, conn.getURL());
				throw new ServalDInterfaceException("unexpected MeshMS status = " + status.meshms_status_code + ", \"" + status.meshms_status_message + "\"");
		}
		throw new ServalDInterfaceException("unexpected HTTP response code: " + conn.getResponseCode());

	}

	public static MeshMSStatus sendMessage(ServalDHttpConnectionFactory connector, SubscriberId sid1, SubscriberId sid2, String text) throws IOException, ServalDInterfaceException, MeshMSException
	{
		HttpURLConnection conn = connector.newServalDHttpConnection("/restful/meshms/" + sid1.toHex() + "/" + sid2.toHex() + "/sendmessage");
		PostHelper helper = new PostHelper(conn);
		helper.connect();
		helper.writeField("message", text);
		helper.close();
		JSONTokeniser json = MeshMSCommon.receiveRestfulResponse(conn, HttpURLConnection.HTTP_CREATED);
		Status status = decodeRestfulStatus(json);
		throwRestfulResponseExceptions(status, conn.getURL());
		return status.meshms_status_code;
	}

	public static MeshMSStatus markAllConversationsRead(ServalDHttpConnectionFactory connector, SubscriberId sid1) throws IOException, ServalDInterfaceException, MeshMSException
	{
		HttpURLConnection conn = connector.newServalDHttpConnection("/restful/meshms/" + sid1.toHex() + "/readall");
		conn.setRequestMethod("POST");
		conn.connect();
		int[] expected_response_codes = { HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_CREATED };
		JSONTokeniser json = MeshMSCommon.receiveRestfulResponse(conn, expected_response_codes);
		Status status = decodeRestfulStatus(json);
		throwRestfulResponseExceptions(status, conn.getURL());
		return status.meshms_status_code;
	}

	public static MeshMSStatus markAllMessagesRead(ServalDHttpConnectionFactory connector, SubscriberId sid1, SubscriberId sid2) throws IOException, ServalDInterfaceException, MeshMSException
	{
		HttpURLConnection conn = connector.newServalDHttpConnection("/restful/meshms/" + sid1.toHex() + "/" + sid2.toHex() + "/readall");
		conn.setRequestMethod("POST");
		conn.connect();
		int[] expected_response_codes = { HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_CREATED };
		JSONTokeniser json = MeshMSCommon.receiveRestfulResponse(conn, expected_response_codes);
		Status status = decodeRestfulStatus(json);
		throwRestfulResponseExceptions(status, conn.getURL());
		return status.meshms_status_code;
	}

	public static MeshMSStatus advanceReadOffset(ServalDHttpConnectionFactory connector, SubscriberId sid1, SubscriberId sid2, long offset) throws IOException, ServalDInterfaceException, MeshMSException
	{
		HttpURLConnection conn = connector.newServalDHttpConnection("/restful/meshms/" + sid1.toHex() + "/" + sid2.toHex() + "/recv/" + offset + "/read");
		conn.setRequestMethod("POST");
		conn.connect();
		int[] expected_response_codes = { HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_CREATED };
		JSONTokeniser json = MeshMSCommon.receiveRestfulResponse(conn, expected_response_codes);
		Status status = decodeRestfulStatus(json);
		throwRestfulResponseExceptions(status, conn.getURL());
		return status.meshms_status_code;
	}

}
