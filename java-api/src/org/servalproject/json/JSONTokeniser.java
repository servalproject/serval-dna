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

package org.servalproject.json;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.Collection;

public class JSONTokeniser {

	private final InputStream underlyingStream;
	private final InputStreamReader reader;
	private boolean closed = false;
	private int pushedChar=-1;
	private Object pushedToken;

	private static final boolean DUMP_JSON_TO_STDERR = false;

	public enum Token {
		START_OBJECT,
		END_OBJECT,
		START_ARRAY,
		END_ARRAY,
		COMMA,
		COLON,
		NULL,
		EOF
	};

	public static class SyntaxException extends JSONInputException
	{
		public SyntaxException(String message) {
			super(message);
		}
		public SyntaxException(String message, Throwable e) {
			super(message, e);
		}
	}

	public static class UnexpectedException extends JSONInputException
	{
		public UnexpectedException(String got) {
			super("unexpected " + got);
		}

		public UnexpectedException(String got, Class expecting) {
			super("unexpected " + got + ", expecting " + expecting.getName());
		}

		public UnexpectedException(String got, Object expecting) {
			super("unexpected " + got + ", expecting " + jsonTokenDescription(expecting));
		}

	}

	public static class UnexpectedEOFException extends UnexpectedException
	{
		public UnexpectedEOFException(Class expecting) {
			super("EOF", expecting);
		}

		public UnexpectedEOFException(Object expecting) {
			super("EOF", expecting);
		}

	}

	public static class UnexpectedTokenException extends UnexpectedException
	{
		public UnexpectedTokenException(Object got) {
			super(jsonTokenDescription(got));
		}

		public UnexpectedTokenException(Object got, Class expecting) {
			super(jsonTokenDescription(got), expecting);
		}

		public UnexpectedTokenException(Object got, Object expecting) {
			super(jsonTokenDescription(got), expecting);
		}

	}

	public JSONTokeniser(InputStream stream) throws UnsupportedEncodingException {
		underlyingStream = stream;
		reader = new InputStreamReader(stream, "UTF-8");
	}

	private int _read()
	{
		if (closed)
			return -1;
		int p = pushedChar;
		pushedChar = -1;
		if (p!=-1)
			return p;
		try {
			int n = this.reader.read();
			if (DUMP_JSON_TO_STDERR && n != -1)
				System.err.print((char) n);
			return n;
		}catch (IOException e){
			return -1;
		}catch (RuntimeException e){
			if (closed)
				return -1;
			throw e;
		}
	}

	private int _read(char[] buf, int offset, int length)
	{
		if (closed)
			return -1;
		if (length==0)
			return 0;

		int p = pushedChar;
		pushedChar = -1;
		if (p!=-1){
			buf[offset] = (char) p;
			return 1;
		}

		try {
			int n = this.reader.read(buf, offset, length);
			if (DUMP_JSON_TO_STDERR && n != -1)
				System.err.print(new String(buf, offset, n));
			return n;
		}catch (IOException e){
			return -1;
		}catch (RuntimeException e){
			if (closed)
				return -1;
			throw e;
		}
	}

	public static void unexpected(Object tok) throws UnexpectedTokenException
	{
		throw new UnexpectedTokenException(tok);
	}

	public static void match(Object tok, Token exactly) throws SyntaxException
	{
		if (tok != exactly)
			throw new SyntaxException("JSON syntax error: expecting " + exactly + ", got " + jsonTokenDescription(tok));
	}

	public void consume(Token exactly) throws SyntaxException, UnexpectedException
	{
		match(nextToken(), exactly);
	}

	public enum Narrow {
		NO_NULL,
		ALLOW_NULL
	};

	public static boolean supportsNarrowTo(Class cls) {
		return cls == Boolean.class
			|| cls == Integer.class
			|| cls == Long.class
			|| cls == Float.class
			|| cls == Double.class
			|| cls == String.class;
	}

	public static Object narrow(Object tok, Narrow opts) throws UnexpectedException
	{
		return narrow(tok, Object.class, opts);
	}

	public static <T> T narrow(Object tok, Class<T> cls) throws UnexpectedException
	{
		return narrow(tok, cls, Narrow.NO_NULL);
	}

	@SuppressWarnings("unchecked")
	public static <T> T narrow(Object tok, Class<T> cls, Narrow opts) throws UnexpectedException
	{
		assert !cls.isAssignableFrom(Token.class); // can only narrow to values
		if (tok == Token.EOF)
			throw new UnexpectedEOFException(cls);
		if (tok == null || tok == Token.NULL){
			if (opts == Narrow.ALLOW_NULL)
				return null;
			throw new UnexpectedTokenException(tok, cls);
		}
		if (tok instanceof Token)
			throw new UnexpectedTokenException(tok, cls);
		// Convert:
		// 		Integer --> Long or Float or Double
		// 		Long --> Float or Double
		// 		Float --> Double
		// 		Double --> Float
		if (cls == Double.class && (tok instanceof Float || tok instanceof Long || tok instanceof Integer))
			tok = ((Number)tok).doubleValue();
		else if (cls == Float.class && (tok instanceof Double || tok instanceof Long || tok instanceof Integer))
			tok = ((Number)tok).floatValue();
		else if (cls == Long.class && tok instanceof Integer)
			tok = ((Number)tok).longValue();
		if (cls.isInstance(tok))
			return (T)tok; // unchecked cast
		throw new UnexpectedTokenException(tok, cls);
	}

	public <T> T consume(Class<T> cls) throws SyntaxException, UnexpectedException
	{
		return consume(cls, Narrow.NO_NULL);
	}

	public <T> T consume(Class<T> cls, Narrow opts) throws SyntaxException, UnexpectedException
	{
		return narrow(nextToken(), cls, opts);
	}

	public Object consume() throws SyntaxException, UnexpectedException
	{
		return consume(Object.class, Narrow.NO_NULL);
	}

	public Object consume(Narrow opts) throws SyntaxException, UnexpectedException
	{
		return consume(Object.class, opts);
	}

	public String consume(String exactly) throws SyntaxException, UnexpectedException
	{
		String tok = consume(String.class);
		if (tok.equals(exactly))
			return tok;
		throw new UnexpectedTokenException(tok, exactly);
	}

	public int consumeArray(Collection<Object> collection, Narrow opts) throws SyntaxException, UnexpectedException
	{
		return consumeArray(collection, Object.class, opts);
	}

	public <T> int consumeArray(Collection<T> collection, Class<T> cls) throws SyntaxException, UnexpectedException
	{
		return consumeArray(collection, cls, Narrow.NO_NULL);
	}

	public <T> int consumeArray(Collection<T> collection, Class<T> cls, Narrow opts) throws SyntaxException, UnexpectedException
	{
		int added = 0;
		consume(Token.START_ARRAY);
		Object tok = nextToken();
		if (tok != Token.END_ARRAY) {
			while (true) {
				collection.add(narrow(tok, cls, opts));
				++added;
				tok = nextToken();
				if (tok == Token.END_ARRAY)
					break;
				match(tok, Token.COMMA);
				tok = nextToken();
			}
		}
		return added;
	}

	public void consumeArray(Object[] array) throws SyntaxException, UnexpectedException
	{
		consumeArray(array, Object.class, Narrow.NO_NULL);
	}

	public void consumeArray(Object[] array, Narrow opts) throws SyntaxException, UnexpectedException
	{
		consumeArray(array, Object.class, opts);
	}

	public <T> void consumeArray(T[] array, Class<T> cls, Narrow opts) throws SyntaxException, UnexpectedException
	{
		consume(Token.START_ARRAY);
		for (int i = 0; i < array.length; ++i) {
			if (i != 0)
				consume(Token.COMMA);
			array[i] = consume(cls, opts);
		}
		consume(Token.END_ARRAY);
	}

	public static boolean jsonIsToken(Object tok)
	{
		return tok instanceof Token
			|| tok instanceof String
			|| tok instanceof Double
			|| tok instanceof Long
			|| tok instanceof Integer
			|| tok instanceof Boolean;
	}

	public static String jsonTokenDescription(Object tok)
	{
		if (tok == null)
			return "null";
		if (tok instanceof String)
			return "\"" + ((String)tok).replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
		if (tok instanceof Number)
			return "" + tok;
		if (tok instanceof Boolean)
			return "" + tok;
		assert tok instanceof Token;
		return tok.toString();
	}

	private void readAll(char[] buf) throws SyntaxException {
		int len = 0;
		while (len < buf.length) {
			int n = _read(buf, len, buf.length - len);
			if (n == -1)
				throw new SyntaxException("EOF in middle of read");
			len += n;
		}
	}

	private void readWord(String word) throws SyntaxException
	{
		int len = word.length();
		char[] buf = new char[len];
		readAll(buf);
		for (int i = 0; i < len; ++i)
			if (buf[i] != word.charAt(i))
				throw new SyntaxException("expecting \"" + word + "\"");
	}

	private int readHex(int digits) throws SyntaxException
	{
		assert digits <= 8;
		char[] buf = new char[digits];
		readAll(buf);
		String hex = new String(buf);
		try {
			return Integer.valueOf(hex, 16);
		}
		catch (NumberFormatException e) {
			throw new SyntaxException("expecting " + digits + " hex digits, got \"" + hex + "\"", e);
		}
	}

	public void pushToken(Object tok)
	{
		assert jsonIsToken(tok);
		assert pushedToken == null;
		pushedToken = tok;
	}

	public Object nextToken() throws SyntaxException
	{
		Object tok = pushedToken;
		if (tok != null) {
			pushedToken = null;
			return tok;
		}
		while (true) {
			int c = _read();
			switch (c) {
			case -1:
				return Token.EOF;
			case '\t':
			case '\r':
			case '\n':
			case ' ':
				break;
			case '{':
				return Token.START_OBJECT;
			case '}':
				return Token.END_OBJECT;
			case '[':
				return Token.START_ARRAY;
			case ']':
				return Token.END_ARRAY;
			case ',':
				return Token.COMMA;
			case ':':
				return Token.COLON;
			case 't':
				pushedChar=c;
				readWord("true");
				return Boolean.TRUE;
			case 'f':
				pushedChar=c;
				readWord("false");
				return Boolean.FALSE;
			case 'n':
				pushedChar=c;
				readWord("null");
				return Token.NULL;
			case '"': {
					StringBuilder sb = new StringBuilder();
					boolean slosh = false;
					while (true) {
						c = _read();
						if (c == -1)
							throw new SyntaxException("unexpected EOF in JSON string");
						if (slosh) {
							switch (c) {
							case '"': case '/': case '\\': sb.append((char)c); break;
							case 'b': sb.append('\b'); break;
							case 'f': sb.append('\f'); break;
							case 'n': sb.append('\n'); break;
							case 'r': sb.append('\r'); break;
							case 't': sb.append('\t'); break;
							case 'u': sb.append((char)readHex(4)); break;
							default: throw new SyntaxException("malformed JSON string");
							}
							slosh = false;
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
						c = _read();
					}
					if (c == '0') {
						sb.append((char)c);
						c = _read();
					}
					else if (Character.isDigit(c)) {
						do {
							sb.append((char)c);
							c = _read();
						}
							while (Character.isDigit(c));
					}
					else
						throw new SyntaxException("malformed JSON number");
					boolean isfloat = false;
					if (c == '.') {
						isfloat = true;
						sb.append((char)c);
						c = _read();
						if (c == -1)
							throw new SyntaxException("unexpected EOF in JSON number");
						if (!Character.isDigit(c))
							throw new SyntaxException("malformed JSON number");
						do {
							sb.append((char)c);
							c = _read();
						}
							while (Character.isDigit(c));
					}
					if (c == 'e' || c == 'E') {
						isfloat = true;
						sb.append((char)c);
						c = _read();
						if (c == '+' || c == '-') {
							sb.append((char)c);
							c = _read();
						}
						if (c == -1)
							throw new SyntaxException("unexpected EOF in JSON number");
						if (!Character.isDigit(c))
							throw new SyntaxException("malformed JSON number");
						do {
							sb.append((char)c);
							c = _read();
						}
							while (Character.isDigit(c));
					}
					pushedChar=c;
					String number = sb.toString();
					try {
						if (isfloat)
							return Double.parseDouble(number);
						else {
							try {
								return Integer.parseInt(number);
							}
							catch (NumberFormatException e) {
							}
							return Long.parseLong(number);
						}
					}
					catch (NumberFormatException e) {
						throw new SyntaxException("malformed JSON number: " + number);
					}
				}
			default:
				throw new SyntaxException("malformed JSON: '" + (char)c + "'");
			}
		}
	}

	public void close() throws IOException
	{
		closed = true;
		this.underlyingStream.close();
		this.reader.close();
	}

}
