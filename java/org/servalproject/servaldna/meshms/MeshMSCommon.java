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
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URL;
import java.net.HttpURLConnection;
import org.servalproject.servaldna.SubscriberId;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.ServalDFailureException;
import org.servalproject.json.JSONTokeniser;
import org.servalproject.json.JSONInputException;

public class MeshMSCommon
{
	protected static JSONTokeniser receiveRestfulResponse(HttpURLConnection conn, int expected_response_code) throws IOException, ServalDInterfaceException, MeshMSException
	{
		if (!conn.getContentType().equals("application/json"))
			throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + conn.getContentType());
		if (conn.getResponseCode() == HttpURLConnection.HTTP_FORBIDDEN) {
			JSONTokeniser json = new JSONTokeniser(new InputStreamReader(conn.getErrorStream(), "US-ASCII"));
			Status status = decodeRestfulStatus(json);
			throwRestfulResponseExceptions(status, conn.getURL());
			throw new ServalDInterfaceException("unexpected MeshMS status = " + status.meshms_status + ", \"" + status.message + "\"");
		}
		if (conn.getResponseCode() != expected_response_code)
			throw new ServalDInterfaceException("unexpected HTTP response code: " + conn.getResponseCode());
		JSONTokeniser json = new JSONTokeniser(new InputStreamReader(conn.getInputStream(), "US-ASCII"));
		return json;
	}

	private static class Status {
		public MeshMSStatus meshms_status;
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
			json.consume(JSONTokeniser.Token.COMMA);
			json.consume("meshms_status_code");
			json.consume(JSONTokeniser.Token.COLON);
			status.meshms_status = MeshMSStatus.fromCode(json.consume(Integer.class));
			json.consume(JSONTokeniser.Token.END_OBJECT);
			json.consume(JSONTokeniser.Token.EOF);
			return status;
		}
		catch (JSONInputException e) {
			throw new ServalDInterfaceException("malformed JSON status response", e);
		}
	}

	protected static void throwRestfulResponseExceptions(Status status, URL url) throws MeshMSException, ServalDFailureException
	{
		switch (status.meshms_status) {
		case OK:
		case UPDATED:
			break;
		case SID_LOCKED:
			throw new MeshMSUnknownIdentityException(url);
		case PROTOCOL_FAULT:
			throw new MeshMSProtocolFaultException(url);
		case ERROR:
			throw new ServalDFailureException("received meshms_status=ERROR(-1) from " + url);
		}
	}

	public static MeshMSStatus sendMessage(ServalDHttpConnectionFactory connector, SubscriberId sid1, SubscriberId sid2, String text) throws IOException, ServalDInterfaceException, MeshMSException
	{
		HttpURLConnection conn = connector.newServalDHttpConnection("/restful/meshms/" + sid1.toHex() + "/" + sid2.toHex() + "/sendmessage");
		String boundary = Long.toHexString(System.currentTimeMillis());
		conn.setRequestMethod("POST");
		conn.setDoOutput(true);
		conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
		conn.connect();
		OutputStream ost = conn.getOutputStream();
		PrintStream wr = new PrintStream(ost, false, "US-ASCII");
		wr.print("--" + boundary + "\r\n");
        wr.print("Content-Disposition: form-data; name=\"message\"\r\n");
        wr.print("Content-Type: text/plain; charset=utf-8\r\n");
        wr.print("\r\n");
        wr.print(text);
        wr.print("\r\n--" + boundary + "--\r\n");
		wr.close();
		JSONTokeniser json = MeshMSCommon.receiveRestfulResponse(conn, HttpURLConnection.HTTP_CREATED);
		Status status = decodeRestfulStatus(json);
		throwRestfulResponseExceptions(status, conn.getURL());
		return status.meshms_status;
	}

}
