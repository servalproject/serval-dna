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

import java.lang.StringBuilder;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.List;
import java.io.IOException;
import java.io.PrintStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import org.servalproject.json.JSONTokeniser;
import org.servalproject.json.JSONInputException;
import org.servalproject.servaldna.BundleId;
import org.servalproject.servaldna.FileHash;
import org.servalproject.servaldna.BundleKey;
import org.servalproject.servaldna.SubscriberId;
import org.servalproject.servaldna.BundleSecret;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.ServalDFailureException;

public class RhizomeCommon
{

	protected static InputStream receiveResponse(HttpURLConnection conn, int expected_response_code) throws IOException, ServalDInterfaceException
	{
		int[] expected_response_codes = { expected_response_code };
		return receiveResponse(conn, expected_response_codes);
	}

	protected static InputStream receiveResponse(HttpURLConnection conn, int[] expected_response_codes) throws IOException, ServalDInterfaceException
	{
		for (int code: expected_response_codes) {
			if (conn.getResponseCode() == code)
				return conn.getInputStream();
		}
		if (!conn.getContentType().equals("application/json"))
			throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + conn.getContentType());
		if (conn.getResponseCode() == HttpURLConnection.HTTP_FORBIDDEN) {
			JSONTokeniser json = new JSONTokeniser(new InputStreamReader(conn.getErrorStream(), "US-ASCII"));
			Status status = decodeRestfulStatus(json);
			throw new ServalDInterfaceException("unexpected Rhizome failure, \"" + status.message + "\"");
		}
		throw new ServalDInterfaceException("unexpected HTTP response code: " + conn.getResponseCode());
	}

	protected static JSONTokeniser receiveRestfulResponse(HttpURLConnection conn, int expected_response_code) throws IOException, ServalDInterfaceException
	{
		int[] expected_response_codes = { expected_response_code };
		return receiveRestfulResponse(conn, expected_response_codes);
	}

	protected static JSONTokeniser receiveRestfulResponse(HttpURLConnection conn, int[] expected_response_codes) throws IOException, ServalDInterfaceException
	{
		InputStream in = receiveResponse(conn, expected_response_codes);
		if (!conn.getContentType().equals("application/json"))
			throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + conn.getContentType());
		return new JSONTokeniser(new InputStreamReader(in, "US-ASCII"));
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

	public static RhizomeManifestBundle rhizomeManifest(ServalDHttpConnectionFactory connector, BundleId bid) throws IOException, ServalDInterfaceException
	{
		HttpURLConnection conn = connector.newServalDHttpConnection("/restful/rhizome/" + bid.toHex() + ".rhm");
		conn.connect();
		InputStream in = RhizomeCommon.receiveResponse(conn, HttpURLConnection.HTTP_OK);
		if (!conn.getContentType().equals("rhizome-manifest/text"))
			throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + conn.getContentType());
		RhizomeManifest manifest;
		try {
			manifest = RhizomeManifest.fromTextFormat(in);
		}
		catch (RhizomeManifestParseException e) {
			throw new ServalDInterfaceException("malformed manifest from daemon", e);
		}
		finally {
			in.close();
		}
		dumpHeaders(conn, System.err);
		long insertTime = headerUnsignedLong(conn, "Serval-Rhizome-Bundle-Inserttime");
		SubscriberId author = header(conn, "Serval-Rhizome-Bundle-Author", SubscriberId.class);
		BundleSecret secret = header(conn, "Serval-Rhizome-Bundle-Secret", BundleSecret.class);
		return new RhizomeManifestBundle(manifest, insertTime, author, secret);
	}

	public static RhizomePayloadRawBundle rhizomePayloadRaw(ServalDHttpConnectionFactory connector, BundleId bid) throws IOException, ServalDInterfaceException
	{
		HttpURLConnection conn = connector.newServalDHttpConnection("/restful/rhizome/" + bid.toHex() + "/raw.bin");
		conn.connect();
		InputStream in = RhizomeCommon.receiveResponse(conn, HttpURLConnection.HTTP_OK);
		if (!conn.getContentType().equals("application/octet-stream"))
			throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + conn.getContentType());
		dumpHeaders(conn, System.err);
		RhizomeManifest manifest = manifestFromHeaders(conn);
		long insertTime = headerUnsignedLong(conn, "Serval-Rhizome-Bundle-Inserttime");
		SubscriberId author = header(conn, "Serval-Rhizome-Bundle-Author", SubscriberId.class);
		BundleSecret secret = header(conn, "Serval-Rhizome-Bundle-Secret", BundleSecret.class);
		return new RhizomePayloadRawBundle(manifest, in, insertTime, author, secret);
	}

	private static void dumpHeaders(HttpURLConnection conn, PrintStream out)
	{
		for (Map.Entry<String,List<String>> e: conn.getHeaderFields().entrySet())
			for (String v: e.getValue())
				out.println("received header " + e.getKey() + ": " + v);
	}

	private static RhizomeManifest manifestFromHeaders(HttpURLConnection conn) throws ServalDInterfaceException
	{
		BundleId id = header(conn, "Serval-Rhizome-Bundle-Id", BundleId.class);
		long version = headerUnsignedLong(conn, "Serval-Rhizome-Bundle-Version");
		long filesize = headerUnsignedLong(conn, "Serval-Rhizome-Bundle-Filesize");
		FileHash filehash = filesize == 0 ? null : header(conn, "Serval-Rhizome-Bundle-Filehash", FileHash.class);
		SubscriberId sender = headerOrNull(conn, "Serval-Rhizome-Bundle-Sender", SubscriberId.class);
		SubscriberId recipient = headerOrNull(conn, "Serval-Rhizome-Bundle-Recipient", SubscriberId.class);
		BundleKey BK = headerOrNull(conn, "Serval-Rhizome-Bundle-BK", BundleKey.class);
		Integer crypt = headerIntegerOrNull(conn, "Serval-Rhizome-Bundle-Crypt");
		Long tail = headerUnsignedLongOrNull(conn, "Serval-Rhizome-Bundle-Tail");
		Long date = headerUnsignedLongOrNull(conn, "Serval-Rhizome-Bundle-Date");
		String service = conn.getHeaderField("Serval-Rhizome-Bundle-Service");
		String name = headerQuotedStringOrNull(conn, "Serval-Rhizome-Bundle-Name");
		return new RhizomeManifest(id, version, filesize, filehash, sender, recipient, BK, crypt, tail, date, service, name);
	}

	private static String headerString(HttpURLConnection conn, String header) throws ServalDInterfaceException
	{
		String str = conn.getHeaderField(header);
		if (str == null)
			throw new ServalDInterfaceException("missing header field: " + header);
		return str;
	}

	private static String headerQuotedStringOrNull(HttpURLConnection conn, String header) throws ServalDInterfaceException
	{
		String quoted = conn.getHeaderField(header);
		if (quoted == null)
			return null;
		if (quoted.length() == 0 || quoted.charAt(0) != '"')
			throw new ServalDInterfaceException("malformed header field: " + header + ": missing quote at start of quoted-string");
		boolean slosh = false;
		boolean end = false;
		StringBuilder b = new StringBuilder(quoted.length());
		for (int i = 1; i < quoted.length(); ++i) {
			char c = quoted.charAt(i);
			if (end)
				throw new ServalDInterfaceException("malformed header field: " + header + ": spurious character after quoted-string");
			if (c < ' ' || c > '~')
				throw new ServalDInterfaceException("malformed header field: " + header + ": invalid character in quoted-string");
			if (slosh) {
				b.append(c);
				slosh = false;
			}
			else if (c == '"')
				end = true;
			else if (c == '\\')
				slosh = true;
			else
				b.append(c);
		}
		if (!end)
			throw new ServalDInterfaceException("malformed header field: " + header + ": missing quote at end of quoted-string");
		return b.toString();
	}

	private static Integer headerIntegerOrNull(HttpURLConnection conn, String header) throws ServalDInterfaceException
	{
		String str = conn.getHeaderField(header);
		if (str == null)
			return null;
		try {
			return Integer.valueOf(str);
		}
		catch (NumberFormatException e) {
		}
		throw new ServalDInterfaceException("invalid header field: " + header + ": " + str);
	}

	private static Long headerUnsignedLongOrNull(HttpURLConnection conn, String header) throws ServalDInterfaceException
	{
		String str = conn.getHeaderField(header);
		if (str == null)
			return null;
		try {
			Long value = Long.valueOf(str);
			if (value >= 0)
				return value;
		}
		catch (NumberFormatException e) {
		}
		throw new ServalDInterfaceException("invalid header field: " + header + ": " + str);
	}

	private static long headerUnsignedLong(HttpURLConnection conn, String header) throws ServalDInterfaceException
	{
		Long value = headerUnsignedLongOrNull(conn, header);
		if (value == null)
			throw new ServalDInterfaceException("missing header field: " + header);
		return value;
	}

	private static <T> T headerOrNull(HttpURLConnection conn, String header, Class<T> cls) throws ServalDInterfaceException
	{
		String str = conn.getHeaderField(header);
		if (str == null)
			return null;
		try {
			return (T) cls.getConstructor(String.class).newInstance(str);
		}
		catch (InvocationTargetException e) {
			throw new ServalDInterfaceException("invalid header field: " + header + ": " + str, e.getTargetException());
		}
		catch (Exception e) {
			throw new ServalDInterfaceException("invalid header field: " + header + ": " + str, e);
		}
	}

	private static <T> T header(HttpURLConnection conn, String header, Class<T> cls) throws ServalDInterfaceException
	{
		T value = headerOrNull(conn, header, cls);
		if (value == null)
			throw new ServalDInterfaceException("missing header field: " + header);
		return value;
	}

}
