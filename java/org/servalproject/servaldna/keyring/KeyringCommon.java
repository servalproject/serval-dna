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
import org.servalproject.json.JSONTokeniser;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.ServalDNotImplementedException;
import org.servalproject.servaldna.SigningKey;
import org.servalproject.servaldna.Subscriber;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.util.List;
import java.util.Map;
import java.util.Vector;

public class KeyringCommon
{

	public static class Status {
		InputStream input_stream;
		JSONTokeniser json;
		public int http_status_code;
		public String http_status_message;
		public KeyringIdentity identity;
	}

	private static void dumpStatus(Status status, PrintStream out)
	{
		out.println("input_stream=" + status.input_stream);
		out.println("http_status_code=" + status.http_status_code);
		out.println("http_status_message=" + status.http_status_message);
		if (status.identity == null) {
			out.println("identity=null");
		} else {
			out.println("identity.subscriber=" + status.identity.subscriber);
			out.println("identity.did=" + status.identity.did);
			out.println("identity.name=" + status.identity.name);
		}
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
		for (int code: expected_response_codes) {
			if (status.http_status_code == code) {
				status.input_stream = conn.getInputStream();
				return status;
			}
		}
		if (!conn.getContentType().equals("application/json"))
			throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + conn.getContentType());
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
				"unexpected Keyring failure, " + quoteString(status.http_status_message)
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
		if (!conn.getContentType().equals("application/json"))
			throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + conn.getContentType());
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
			Object tok = json.nextToken();
			if (tok == JSONTokeniser.Token.COMMA) {
				json.consume("identity");
				json.consume(JSONTokeniser.Token.COLON);
				json.consume(JSONTokeniser.Token.START_OBJECT);
				json.consume("sid");
				json.consume(JSONTokeniser.Token.COLON);
				SubscriberId sid = new SubscriberId(json.consume(String.class));
				json.consume(JSONTokeniser.Token.COMMA);
				json.consume("sign");
				json.consume(JSONTokeniser.Token.COLON);
				SigningKey sas = new SigningKey(json.consume(String.class));
				String did = null;
				String name = null;
				tok = json.nextToken();
				if (tok == JSONTokeniser.Token.COMMA) {
					json.consume("did");
					json.consume(JSONTokeniser.Token.COLON);
					did = json.consume(String.class);
					tok = json.nextToken();
				}
				if (tok == JSONTokeniser.Token.COMMA) {
					json.consume("name");
					json.consume(JSONTokeniser.Token.COLON);
					name = json.consume(String.class);
					tok = json.nextToken();
				}
				json.match(tok, JSONTokeniser.Token.END_OBJECT);
				tok = json.nextToken();
				status.identity = new KeyringIdentity(0, new Subscriber(sid, sas, true), did, name);
			}
			json.match(tok, JSONTokeniser.Token.END_OBJECT);
			json.consume(JSONTokeniser.Token.EOF);
		}
		catch (SubscriberId.InvalidHexException e) {
			throw new ServalDInterfaceException("malformed JSON status response", e);
		}
		catch (JSONInputException e) {
			throw new ServalDInterfaceException("malformed JSON status response", e);
		}
	}

	private static void dumpHeaders(HttpURLConnection conn, PrintStream out)
	{
		for (Map.Entry<String,List<String>> e: conn.getHeaderFields().entrySet())
			for (String v: e.getValue())
				out.println("received header " + e.getKey() + ": " + v);
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
		HttpURLConnection conn = connector.newServalDHttpConnection("/restful/keyring/" + sid.toHex() + "/set", query_params);
		conn.connect();
		Status status = receiveRestfulResponse(conn, HttpURLConnection.HTTP_OK);
		try {
			decodeRestfulStatus(status);
			dumpStatus(status, System.err);
			if (status.identity == null)
				throw new ServalDInterfaceException("invalid JSON response; missing identity");

			return status.identity;
		}
		finally {
			if (status.input_stream != null)
				status.input_stream.close();
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
		HttpURLConnection conn = connector.newServalDHttpConnection("/restful/keyring/add", query_params);
		conn.connect();
		Status status = receiveRestfulResponse(conn, HttpURLConnection.HTTP_OK);
		try {
			decodeRestfulStatus(status);
			dumpStatus(status, System.err);
			if (status.identity == null)
				throw new ServalDInterfaceException("invalid JSON response; missing identity");

			return status.identity;
		}
		finally {
			if (status.input_stream != null)
				status.input_stream.close();
		}
	}

}
