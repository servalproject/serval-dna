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
import java.lang.StringBuilder;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.PushbackReader;
import java.util.Collection;
import java.util.Vector;
import java.net.HttpURLConnection;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SubscriberId;

public class MeshMSConversationList {

	private ServalDHttpConnectionFactory httpConnector;
	private SubscriberId sid;
	private HttpURLConnection httpConnection;
	private PushbackReader reader;
	private Vector<String> headers;
	int columnIndex__id;
	int columnIndex_my_sid;
	int columnIndex_their_sid;
	int columnIndex_read;
	int columnIndex_last_message;
	int columnIndex_read_offset;
	int rowCount;

	public MeshMSConversationList(ServalDHttpConnectionFactory connector, SubscriberId sid)
	{
		this.httpConnector = connector;
		this.sid = sid;
	}

	public void connect() throws ServalDInterfaceException, IOException
	{
		columnIndex__id = -1;
		columnIndex_my_sid = -1;
		columnIndex_their_sid = -1;
		columnIndex_read = -1;
		columnIndex_last_message = -1;
		columnIndex_read_offset = -1;
		rowCount = 0;
		httpConnection = httpConnector.newServalDHttpConnection("/restful/meshms/" + sid.toHex() + "/conversationlist.json");
		httpConnection.connect();
		reader = new PushbackReader(new InputStreamReader(httpConnection.getInputStream(), "US-ASCII"));
		consume(reader, JsonToken.START_OBJECT);
		consume(reader, "header");
		consume(reader, JsonToken.COLON);
		headers = new Vector<String>();
		consumeArray(reader, headers, String.class);
		if (headers.size() < 1)
			throw new ServalDInterfaceException("empty JSON headers array");
		for (int i = 0; i < headers.size(); ++i) {
			String header = headers.get(i);
			if (header.equals("_id"))
				columnIndex__id = i;
			else if (header.equals("my_sid"))
				columnIndex_my_sid = i;
			else if (header.equals("their_sid"))
				columnIndex_their_sid = i;
			else if (header.equals("read"))
				columnIndex_read = i;
			else if (header.equals("last_message"))
				columnIndex_last_message = i;
			else if (header.equals("read_offset"))
				columnIndex_read_offset = i;
		}
		if (columnIndex__id == -1)
			throw new ServalDInterfaceException("missing JSON column: _id");
		if (columnIndex_my_sid == -1)
			throw new ServalDInterfaceException("missing JSON column: my_sid");
		if (columnIndex_their_sid == -1)
			throw new ServalDInterfaceException("missing JSON column: their_sid");
		if (columnIndex_read == -1)
			throw new ServalDInterfaceException("missing JSON column: read");
		if (columnIndex_last_message == -1)
			throw new ServalDInterfaceException("missing JSON column: last_message");
		if (columnIndex_read_offset == -1)
			throw new ServalDInterfaceException("missing JSON column: read_offset");
		consume(reader, JsonToken.COMMA);
		consume(reader, "rows");
		consume(reader, JsonToken.COLON);
		consume(reader, JsonToken.START_ARRAY);
	}

	public MeshMSConversation nextConversation() throws ServalDInterfaceException, IOException
	{
		Object tok = nextJsonToken(reader);
		if (tok == JsonToken.END_ARRAY) {
			consume(reader, JsonToken.END_OBJECT);
			consume(reader, JsonToken.EOF);
			return null;
		}
		if (rowCount != 0) {
			match(tok, JsonToken.COMMA);
			tok = nextJsonToken(reader);
		}
		match(tok, JsonToken.START_ARRAY);
		Object[] row = new Object[headers.size()];
		for (int i = 0; i < headers.size(); ++i) {
			if (i != 0)
				consume(reader, JsonToken.COMMA);
			row[i] = consume(reader);
		}
		consume(reader, JsonToken.END_ARRAY);
		int _id = narrow(row[columnIndex__id], Integer.class);
		SubscriberId my_sid;
		try {
			my_sid = new SubscriberId(narrow(row[columnIndex_my_sid], String.class));
		}
		catch (SubscriberId.InvalidHexException e) {
			throw new ServalDInterfaceException("invalid JSON column value: my_sid", e);
		}
		SubscriberId their_sid;
		try {
			their_sid = new SubscriberId(narrow(row[columnIndex_their_sid], String.class));
		}
		catch (SubscriberId.InvalidHexException e) {
			throw new ServalDInterfaceException("invalid JSON column value: their_sid", e);
		}
		boolean is_read = narrow(row[columnIndex_read], Boolean.class);
		int last_message = narrow(row[columnIndex_last_message], Integer.class);
		int read_offset = narrow(row[columnIndex_read_offset], Integer.class);
		return new MeshMSConversation(rowCount++, _id, my_sid, their_sid, is_read, last_message, read_offset);
	}

	public void close() throws IOException
	{
		if (reader != null) {
			reader.close();
			reader = null;
		}
	}

	static void match(Object tok, JsonToken exactly) throws ServalDInterfaceException
	{
		if (tok != exactly)
			throw new ServalDInterfaceException("unexpected JSON token " + exactly + ", got: " + jsonTokenDescription(tok));
	}

	static void consume(PushbackReader rd, JsonToken exactly) throws ServalDInterfaceException, IOException
	{
		match(nextJsonToken(rd), exactly);
	}

	@SuppressWarnings("unchecked")
	static <T> T narrow(Object tok, Class<T> cls) throws ServalDInterfaceException
	{
		assert !cls.isAssignableFrom(JsonToken.class); // can only narrow to values
		if (tok == JsonToken.EOF)
			throw new ServalDInterfaceException("unexpected EOF");
		if (tok instanceof JsonToken)
			throw new ServalDInterfaceException("expecting JSON " + cls.getName() + ", got: " + tok);
		// Convert:
		// 		Integer --> Float or Double
		// 		Float --> Double
		// 		Double --> Float
		if (cls == Double.class && (tok instanceof Float || tok instanceof Integer))
			tok = new Double(((Number)tok).doubleValue());
		else if (cls == Float.class && (tok instanceof Double || tok instanceof Integer))
			tok = new Float(((Number)tok).floatValue());
		if (cls.isInstance(tok))
			return (T)tok;
		throw new ServalDInterfaceException("expecting JSON " + cls.getName() + ", got: " + jsonTokenDescription(tok));
	}

	static <T> T consume(PushbackReader rd, Class<T> cls) throws ServalDInterfaceException, IOException
	{
		return narrow(nextJsonToken(rd), cls);
	}

	static Object consume(PushbackReader rd) throws ServalDInterfaceException, IOException
	{
		return consume(rd, Object.class);
	}

	static String consume(PushbackReader rd, String exactly) throws ServalDInterfaceException, IOException
	{
		String tok = consume(rd, String.class);
		if (tok.equals(exactly))
			return tok;
		throw new ServalDInterfaceException("unexpected JSON String \"" + exactly + "\", got: " + jsonTokenDescription(tok));
	}

	static <T> int consumeArray(PushbackReader rd, Collection<T> collection, Class<T> cls) throws ServalDInterfaceException, IOException
	{
		int added = 0;
		consume(rd, JsonToken.START_ARRAY);
		Object tok = nextJsonToken(rd);
		if (tok != JsonToken.END_ARRAY) {
			while (true) {
				try {
					collection.add(narrow(tok, cls));
					++added;
				}
				catch (ClassCastException e) {
					throw new ServalDInterfaceException("unexpected JSON token: " + jsonTokenDescription(tok));
				}
				tok = nextJsonToken(rd);
				if (tok == JsonToken.END_ARRAY)
					break;
				match(tok, JsonToken.COMMA);
				tok = nextJsonToken(rd);
			}
		}
		return added;
	}

	enum JsonToken {
		START_OBJECT,
		END_OBJECT,
		START_ARRAY,
		END_ARRAY,
		COMMA,
		COLON,
		NULL,
		EOF
	};

	static boolean jsonIsToken(Object tok)
	{
		return tok instanceof JsonToken || tok instanceof String || tok instanceof Double || tok instanceof Integer || tok instanceof Boolean;
	}

	static String jsonTokenDescription(Object tok)
	{
		if (tok instanceof String)
			return "\"" + tok + "\"";
		if (tok instanceof Number)
			return "" + tok;
		if (tok instanceof Boolean)
			return "" + tok;
		assert tok instanceof JsonToken;
		return tok.toString();
	}

	static void readAll(Reader rd, char[] word) throws ServalDInterfaceException, IOException
	{
		int len = 0;
		while (len < word.length) {
			int n = rd.read(word, len, word.length - len);
			if (n == -1)
				throw new ServalDInterfaceException("unexpected EOF");
			len += n;
		}
	}

	static Object nextJsonToken(PushbackReader rd) throws ServalDInterfaceException, IOException
	{
		while (true) {
			int c = rd.read();
			switch (c) {
			case -1:
				return JsonToken.EOF;
			case '\t':
			case '\r':
			case '\n':
			case ' ':
				break;
			case '{':
				return JsonToken.START_OBJECT;
			case '}':
				return JsonToken.END_OBJECT;
			case '[':
				return JsonToken.START_ARRAY;
			case ']':
				return JsonToken.END_ARRAY;
			case ',':
				return JsonToken.COMMA;
			case ':':
				return JsonToken.COLON;
			case 't': {
					char[] word = new char[3];
					readAll(rd, word);
					if (word[0] == 'r' && word[1] == 'u' && word[2] == 'e')
						return Boolean.TRUE;
				}
				throw new ServalDInterfaceException("malformed JSON");
			case 'f': {
					char[] word = new char[4];
					readAll(rd, word);
					if (word[0] == 'a' && word[1] == 'l' && word[2] == 's' && word[3] == 'e')
						return Boolean.FALSE;
				}
				throw new ServalDInterfaceException("malformed JSON");
			case 'n': {
					char[] word = new char[3];
					readAll(rd, word);
					if (word[0] == 'u' && word[1] == 'l' && word[2] == 'l')
						return JsonToken.NULL;
				}
				throw new ServalDInterfaceException("malformed JSON");
			case '"': {
					StringBuilder sb = new StringBuilder();
					boolean slosh = false;
					while (true) {
						c = rd.read();
						if (c == -1)
							throw new ServalDInterfaceException("unexpected EOF in JSON string");
						if (slosh) {
							switch (c) {
							case '"': case '/': case '\\': sb.append('"'); break;
							case 'b': sb.append('\b'); break;
							case 'f': sb.append('\f'); break;
							case 'n': sb.append('\n'); break;
							case 'r': sb.append('\r'); break;
							case 't': sb.append('\t'); break;
							case 'u':
								char[] hex = new char[4];
								readAll(rd, hex);
								int code = Integer.valueOf(new String(hex), 16);
								if (code >= 0 && code <= 0xffff) {
									sb.append((char)code);
									break;
								}
								// fall through
							default:
								throw new ServalDInterfaceException("malformed JSON string");
							}
						}
						else {
							switch (c) {
							case '"':
								return sb.toString();
							case '\\':
								slosh = true;
								break;
							default:
								sb.append((char)c);
								break;
							}
						}
					}
				}
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
			case '-': {
					StringBuilder sb = new StringBuilder();
					if (c == '-') {
						sb.append((char)c);
						c = rd.read();
					}
					if (c == '0') {
						sb.append((char)c);
						c = rd.read();
					}
					else if (Character.isDigit(c)) {
						do {
							sb.append((char)c);
							c = rd.read();
						}
							while (Character.isDigit(c));
					}
					else
						throw new ServalDInterfaceException("malformed JSON number");
					boolean isfloat = false;
					if (c == '.') {
						isfloat = true;
						sb.append((char)c);
						c = rd.read();
						if (c == -1)
							throw new ServalDInterfaceException("unexpected EOF in JSON number");
						if (!Character.isDigit(c))
							throw new ServalDInterfaceException("malformed JSON number");
						do {
							sb.append((char)c);
							c = rd.read();
						}
							while (Character.isDigit(c));
					}
					if (c == 'e' || c == 'E') {
						isfloat = true;
						sb.append((char)c);
						c = rd.read();
						if (c == '+' || c == '-') {
							sb.append((char)c);
							c = rd.read();
						}
						if (c == -1)
							throw new ServalDInterfaceException("unexpected EOF in JSON number");
						if (!Character.isDigit(c))
							throw new ServalDInterfaceException("malformed JSON number");
						do {
							sb.append((char)c);
							c = rd.read();
						}
							while (Character.isDigit(c));
					}
					rd.unread(c);
					String number = sb.toString();
					try {
						if (isfloat)
							return Double.parseDouble(number);
						else
							return Integer.parseInt(number);
					}
					catch (NumberFormatException e) {
						throw new ServalDInterfaceException("malformed JSON number: " + number);
					}
				}
			default:
				throw new ServalDInterfaceException("malformed JSON: '" + (char)c + "'");
			}
		}
	}

}
