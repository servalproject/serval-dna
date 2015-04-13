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
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.List;
import java.io.IOException;
import java.io.PrintStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
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
import org.servalproject.servaldna.ServalDNotImplementedException;

public class RhizomeCommon
{

	private static class Status {
		InputStream input_stream;
		public int http_status_code;
		public String http_status_message;
		RhizomeBundleStatus bundle_status_code;
		String bundle_status_message;
		RhizomePayloadStatus payload_status_code;
		String payload_status_message;
	}

	private static void dumpStatus(Status status, PrintStream out)
	{
		out.println("input_stream=" + status.input_stream);
		out.println("http_status_code=" + status.http_status_code);
		out.println("http_status_message=" + status.http_status_message);
		out.println("bundle_status_code=" + status.bundle_status_code);
		out.println("bundle_status_message=" + status.bundle_status_message);
		out.println("payload_status_code=" + status.payload_status_code);
		out.println("payload_status_message=" + status.payload_status_message);
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
			JSONTokeniser json = new JSONTokeniser(new InputStreamReader(conn.getErrorStream(), "US-ASCII"));
			decodeRestfulStatus(status, json);
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
				"unexpected Rhizome failure, " + quoteString(status.http_status_message)
				+ (status.bundle_status_code == null ? "" : ", " + status.bundle_status_code)
				+ (status.bundle_status_message == null ? "" : " " + quoteString(status.bundle_status_message))
				+ (status.payload_status_code == null ? "" : ", " + status.payload_status_code)
				+ (status.payload_status_message == null ? "" : " " + quoteString(status.payload_status_message))
				+ " from " + conn.getURL()
			);
	}

	protected static JSONTokeniser receiveRestfulResponse(HttpURLConnection conn, int expected_response_code) throws IOException, ServalDInterfaceException
	{
		int[] expected_response_codes = { expected_response_code };
		return receiveRestfulResponse(conn, expected_response_codes);
	}

	protected static JSONTokeniser receiveRestfulResponse(HttpURLConnection conn, int[] expected_response_codes) throws IOException, ServalDInterfaceException
	{
		Status status = receiveResponse(conn, expected_response_codes);
		if (!conn.getContentType().equals("application/json"))
			throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + conn.getContentType());
		return new JSONTokeniser(new InputStreamReader(status.input_stream, "US-ASCII"));
	}

	protected static void decodeHeaderBundleStatus(Status status, HttpURLConnection conn) throws ServalDInterfaceException
	{
		status.bundle_status_code = header(conn,  "Serval-Rhizome-Result-Bundle-Status-Code", RhizomeBundleStatus.class);
		status.bundle_status_message = headerString(conn,  "Serval-Rhizome-Result-Bundle-Status-Message");
	}

	protected static void decodeHeaderPayloadStatus(Status status, HttpURLConnection conn) throws ServalDInterfaceException
	{
		status.payload_status_code = header(conn,  "Serval-Rhizome-Result-Payload-Status-Code", RhizomePayloadStatus.class);
		status.payload_status_message = headerString(conn,  "Serval-Rhizome-Result-Payload-Status-Message");
	}

	protected static void decodeHeaderPayloadStatusOrNull(Status status, HttpURLConnection conn) throws ServalDInterfaceException
	{
		status.payload_status_code = headerOrNull(conn,  "Serval-Rhizome-Result-Payload-Status-Code", RhizomePayloadStatus.class);
		status.payload_status_message = headerStringOrNull(conn,  "Serval-Rhizome-Result-Payload-Status-Message");
	}

	protected static void decodeRestfulStatus(Status status, JSONTokeniser json) throws IOException, ServalDInterfaceException
	{
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
			while (tok == JSONTokeniser.Token.COMMA) {
				String label = json.consume(String.class);
				json.consume(JSONTokeniser.Token.COLON);
				if (label.equals("rhizome_bundle_status_code")) {
					RhizomeBundleStatus bs = RhizomeBundleStatus.fromCode(json.consume(Integer.class));
					if (status.bundle_status_code == null)
						status.bundle_status_code = bs;
					else if (status.bundle_status_code != bs)
						throw new ServalDInterfaceException("JSON/header conflict"
								+ ", rhizome_bundle_status_code=" + bs.code
								+ " but Serval-Rhizome-Result-Bundle-Status-Code: " + status.bundle_status_code.code);
				}
				else if (label.equals("rhizome_bundle_status_message")) {
					String message = json.consume(String.class);
					if (status.bundle_status_message == null)
						status.bundle_status_message = message;
					else if (!status.bundle_status_message.equals(message))
						throw new ServalDInterfaceException("JSON/header conflict"
								+ ", rhizome_bundle_status_message=" + message
								+ " but Serval-Rhizome-Result-Bundle-Status-Message: " + status.bundle_status_message);
				}
				else if (label.equals("rhizome_payload_status_code")) {
					RhizomePayloadStatus bs = RhizomePayloadStatus.fromCode(json.consume(Integer.class));
					if (status.payload_status_code == null)
						status.payload_status_code = bs;
					else if (status.payload_status_code != bs)
						throw new ServalDInterfaceException("JSON/header conflict"
								+ ", rhizome_payload_status_code=" + bs.code
								+ " but Serval-Rhizome-Result-Payload-Status-Code: " + status.payload_status_code.code);
				}
				else if (label.equals("rhizome_payload_status_message")) {
					String message = json.consume(String.class);
					if (status.payload_status_message == null)
						status.payload_status_message = message;
					else if (!status.payload_status_message.equals(message))
						throw new ServalDInterfaceException("JSON/header conflict"
								+ ", rhizome_payload_status_message=" + message
								+ " but Serval-Rhizome-Result-Payload-Status-Code: " + status.payload_status_message);
				}
				else
					json.unexpected(label);
				tok = json.nextToken();
			}
			json.match(tok, JSONTokeniser.Token.END_OBJECT);
			json.consume(JSONTokeniser.Token.EOF);
		}
		catch (JSONInputException e) {
			throw new ServalDInterfaceException("malformed JSON status response", e);
		}
	}

	public static RhizomeManifestBundle rhizomeManifest(ServalDHttpConnectionFactory connector, BundleId bid)
		throws IOException, ServalDInterfaceException
	{
		HttpURLConnection conn = connector.newServalDHttpConnection("/restful/rhizome/" + bid.toHex() + ".rhm");
		conn.connect();
		Status status = RhizomeCommon.receiveResponse(conn, HttpURLConnection.HTTP_OK);
		try {
			dumpHeaders(conn, System.err);
			decodeHeaderBundleStatus(status, conn);
			dumpStatus(status, System.err);
			switch (status.bundle_status_code) {
			case NEW:
				return null;
			case SAME:
				if (!conn.getContentType().equals("rhizome-manifest/text"))
					throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + conn.getContentType());
				RhizomeManifest manifest = RhizomeManifest.fromTextFormat(status.input_stream);
				BundleExtra extra = bundleExtraFromHeaders(conn);
				return new RhizomeManifestBundle(manifest, extra.rowId, extra.insertTime, extra.author, extra.secret);
			case ERROR:
				throw new ServalDFailureException("received rhizome_bundle_status_code=ERROR(-1) from " + conn.getURL());
			}
		}
		catch (RhizomeManifestParseException e) {
			throw new ServalDInterfaceException("malformed manifest from daemon", e);
		}
		finally {
			if (status.input_stream != null)
				status.input_stream.close();
		}
		throw unexpectedResponse(conn, status);
	}

	public static RhizomePayloadRawBundle rhizomePayloadRaw(ServalDHttpConnectionFactory connector, BundleId bid)
		throws IOException, ServalDInterfaceException
	{
		HttpURLConnection conn = connector.newServalDHttpConnection("/restful/rhizome/" + bid.toHex() + "/raw.bin");
		conn.connect();
		Status status = RhizomeCommon.receiveResponse(conn, HttpURLConnection.HTTP_OK);
		try {
			dumpHeaders(conn, System.err);
			decodeHeaderBundleStatus(status, conn);
			dumpStatus(status, System.err);
			switch (status.bundle_status_code) {
			case ERROR:
				throw new ServalDFailureException("received rhizome_bundle_status_code=ERROR(-1) from " + conn.getURL());
			case NEW: // No manifest
				return null;
			case SAME:
				decodeHeaderPayloadStatus(status, conn);
				switch (status.payload_status_code) {
				case ERROR:
					throw new ServalDFailureException("received rhizome_payload_status_code=ERROR(-1) from " + conn.getURL());
				case NEW:
					// The manifest is known but the payload is unavailable, so return a bundle
					// object with a null input stream.
					// FALL THROUGH
				case EMPTY:
					if (status.input_stream != null) {
						status.input_stream.close();
						status.input_stream = null;
					}
					// FALL THROUGH
				case STORED: {
						if (status.input_stream != null && !conn.getContentType().equals("application/octet-stream"))
							throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + conn.getContentType());
						RhizomeManifest manifest = manifestFromHeaders(conn);
						BundleExtra extra = bundleExtraFromHeaders(conn);
						RhizomePayloadRawBundle ret = new RhizomePayloadRawBundle(manifest, status.input_stream, extra.rowId, extra.insertTime, extra.author, extra.secret);
						status.input_stream = null; // don't close when we return
						return ret;
					}
				}
			}
		}
		finally {
			if (status.input_stream != null)
				status.input_stream.close();
		}
		throw unexpectedResponse(conn, status);
	}

	public static RhizomePayloadBundle rhizomePayload(ServalDHttpConnectionFactory connector, BundleId bid)
		throws IOException, ServalDInterfaceException, RhizomeDecryptionException
	{
		HttpURLConnection conn = connector.newServalDHttpConnection("/restful/rhizome/" + bid.toHex() + "/decrypted.bin");
		conn.connect();
		Status status = RhizomeCommon.receiveResponse(conn, HttpURLConnection.HTTP_OK);
		try {
			dumpHeaders(conn, System.err);
			decodeHeaderBundleStatus(status, conn);
			dumpStatus(status, System.err);
			switch (status.bundle_status_code) {
			case ERROR:
				throw new ServalDFailureException("received rhizome_bundle_status_code=ERROR(-1) from " + conn.getURL());
			case NEW: // No manifest
				return null;
			case SAME:
				decodeHeaderPayloadStatus(status, conn);
				switch (status.payload_status_code) {
				case ERROR:
					throw new ServalDFailureException("received rhizome_payload_status_code=ERROR(-1) from " + conn.getURL());
				case CRYPTO_FAIL:
					throw new RhizomeDecryptionException(conn.getURL());
				case NEW:
					// The manifest is known but the payload is unavailable, so return a bundle
					// object with a null input stream.
					// FALL THROUGH
				case EMPTY:
					if (status.input_stream != null) {
						status.input_stream.close();
						status.input_stream = null;
					}
					// FALL THROUGH
				case STORED: {
						if (status.input_stream != null && !conn.getContentType().equals("application/octet-stream"))
							throw new ServalDInterfaceException("unexpected HTTP Content-Type: " + conn.getContentType());
						RhizomeManifest manifest = manifestFromHeaders(conn);
						BundleExtra extra = bundleExtraFromHeaders(conn);
						RhizomePayloadBundle ret = new RhizomePayloadBundle(manifest, status.input_stream, extra.rowId, extra.insertTime, extra.author, extra.secret);
						status.input_stream = null; // don't close when we return
						return ret;
					}
				}
			}
		}
		finally {
			if (status.input_stream != null)
				status.input_stream.close();
		}
		throw unexpectedResponse(conn, status);
	}

	public static RhizomeInsertBundle rhizomeInsert(ServalDHttpConnectionFactory connector,
													SubscriberId author,
													RhizomeIncompleteManifest manifest,
													BundleSecret secret)
		throws	ServalDInterfaceException,
				IOException,
				RhizomeInvalidManifestException,
				RhizomeFakeManifestException,
				RhizomeInconsistencyException,
				RhizomeReadOnlyException,
				RhizomeEncryptionException
	{
		return rhizomeInsert(connector, author, manifest, secret, null, null);
	}

	public static RhizomeInsertBundle rhizomeInsert(ServalDHttpConnectionFactory connector,
													SubscriberId author,
													RhizomeIncompleteManifest manifest,
													BundleSecret secret,
													InputStream payloadStream,
													String fileName)
		throws	ServalDInterfaceException,
				IOException,
				RhizomeInvalidManifestException,
				RhizomeFakeManifestException,
				RhizomeInconsistencyException,
				RhizomeReadOnlyException,
				RhizomeEncryptionException
	{
		HttpURLConnection conn = connector.newServalDHttpConnection("/restful/rhizome/insert");
		String boundary = Long.toHexString(System.currentTimeMillis());
		conn.setRequestMethod("POST");
		conn.setDoOutput(true);
		conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
		conn.connect();
		OutputStream ost = conn.getOutputStream();
		PrintStream wr = new PrintStream(ost, false, "US-ASCII");
		wr.print(new Object(){}.getClass().getEnclosingClass().getName());
		if (author != null) {
			wr.print("\r\n--" + boundary + "\r\n");
			wr.print("Content-Disposition: form-data; name=\"bundle-author\"\r\n");
			wr.print("Content-Type: serval-mesh/sid\r\n");
			wr.print("Content-Transfer-Encoding: hex\r\n");
			wr.print("\r\n");
			wr.print(author.toHex());
		}
		if (secret != null) {
			wr.print("\r\n--" + boundary + "\r\n");
			wr.print("Content-Disposition: form-data; name=\"bundle-secret\"\r\n");
			wr.print("Content-Type: rhizome/bundle-secret\r\n");
			wr.print("Content-Transfer-Encoding: hex\r\n");
			wr.print("\r\n");
			wr.print(secret.toHex());
		}
		wr.print("\r\n--" + boundary + "\r\n");
        wr.print("Content-Disposition: form-data; name=\"manifest\"\r\n");
        wr.print("Content-Type: rhizome/manifest; format=\"text+binarysig\"\r\n");
		wr.print("Content-Transfer-Encoding: binary\r\n");
        wr.print("\r\n");
		wr.flush();
		manifest.toTextFormat(ost);
		if (payloadStream != null) {
			wr.print("\r\n--" + boundary + "\r\n");
			wr.print("Content-Disposition: form-data; name=\"payload\"");
			if (fileName != null) {
				wr.print("; filename=");
				wr.print(quoteString(fileName));
			}
			wr.print("\r\n");
			wr.print("Content-Type: application/octet-stream\r\n");
			wr.print("Content-Transfer-Encoding: binary\r\n");
			wr.print("\r\n");
			wr.flush();
			byte[] buffer = new byte[4096];
			int n;
			while ((n = payloadStream.read(buffer)) > 0)
				ost.write(buffer, 0, n);
		}
        wr.print("\r\n--" + boundary + "--\r\n");
		wr.close();
		int[] expected_response_codes = { HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_CREATED };
		Status status = RhizomeCommon.receiveResponse(conn, expected_response_codes);
		try {
			dumpHeaders(conn, System.err);
			decodeHeaderPayloadStatusOrNull(status, conn);
			if (status.payload_status_code != null) {
				switch (status.payload_status_code) {
				case ERROR:
					dumpStatus(status, System.err);
					throw new ServalDFailureException("received Rhizome payload_status=ERROR " + quoteString(status.payload_status_message) + " from " + conn.getURL());
				case EMPTY:
				case NEW:
				case STORED:
					break;
				case TOO_BIG:
				case EVICTED:
					dumpStatus(status, System.err);
					return null;
				case WRONG_SIZE:
				case WRONG_HASH:
					dumpStatus(status, System.err);
					throw new RhizomeInconsistencyException(status.payload_status_message, conn.getURL());
				case CRYPTO_FAIL:
					dumpStatus(status, System.err);
					throw new RhizomeEncryptionException(status.payload_status_message, conn.getURL());
				}
			}
			decodeHeaderBundleStatus(status, conn);
			dumpStatus(status, System.err);
			switch (status.bundle_status_code) {
			case ERROR:
				throw new ServalDFailureException("received Rhizome bundle_status=ERROR " + quoteString(status.bundle_status_message) + " from " + conn.getURL());
			case NEW:
			case SAME:
			case DUPLICATE:
			case OLD:
			case NO_ROOM: {
					if (!conn.getContentType().equals("rhizome-manifest/text"))
						throw new ServalDInterfaceException("unexpected HTTP Content-Type " + conn.getContentType() + " from " + conn.getURL());
					RhizomeManifest returned_manifest = RhizomeManifest.fromTextFormat(status.input_stream);
					BundleExtra extra = bundleExtraFromHeaders(conn);
					return new RhizomeInsertBundle(status.bundle_status_code, returned_manifest, extra.rowId, extra.insertTime, extra.author, extra.secret);
				}
			case INVALID:
				throw new RhizomeInvalidManifestException(status.bundle_status_message, conn.getURL());
			case FAKE:
				throw new RhizomeFakeManifestException(status.bundle_status_message, conn.getURL());
			case INCONSISTENT:
				throw new RhizomeInconsistencyException(status.bundle_status_message, conn.getURL());
			case READONLY:
				throw new RhizomeReadOnlyException(status.bundle_status_message, conn.getURL());
			}
		}
		catch (RhizomeManifestParseException e) {
			throw new ServalDInterfaceException("malformed manifest from daemon", e);
		}
		finally {
			if (status.input_stream != null)
				status.input_stream.close();
		}
		dumpStatus(status, System.err);
		throw unexpectedResponse(conn, status);
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

	private static class BundleExtra {
		public Long rowId;
		public Long insertTime;
		public SubscriberId author;
		public BundleSecret secret;
	}

	private static BundleExtra bundleExtraFromHeaders(HttpURLConnection conn) throws ServalDInterfaceException
	{
		BundleExtra extra = new BundleExtra();
		extra.rowId = headerUnsignedLongOrNull(conn, "Serval-Rhizome-Bundle-Rowid");
		extra.insertTime = headerUnsignedLongOrNull(conn, "Serval-Rhizome-Bundle-Inserttime");
		extra.author = headerOrNull(conn, "Serval-Rhizome-Bundle-Author", SubscriberId.class);
		extra.secret = headerOrNull(conn, "Serval-Rhizome-Bundle-Secret", BundleSecret.class);
		return extra;
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

	private static String headerStringOrNull(HttpURLConnection conn, String header) throws ServalDInterfaceException
	{
		return conn.getHeaderField(header);
	}

	private static String headerString(HttpURLConnection conn, String header) throws ServalDInterfaceException
	{
		String str = headerStringOrNull(conn, header);
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
		try {
			try {
				Constructor<T> constructor = cls.getConstructor(String.class);
				if (str == null)
					return null;
				return constructor.newInstance(str);
			}
			catch (NoSuchMethodException e) {
			}
			try {
				Method method = cls.getMethod("fromCode", Integer.TYPE);
				if ((method.getModifiers() & Modifier.STATIC) != 0 && method.getReturnType() == cls) {
					Integer integer = headerIntegerOrNull(conn, header);
					if (integer == null)
						return null;
					return cls.cast(method.invoke(null, integer));
				}
			}
			catch (NoSuchMethodException e) {
			}
			throw new ServalDInterfaceException("don't know how to instantiate: " + cls.getName());
		}
		catch (ServalDInterfaceException e) {
			throw e;
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
