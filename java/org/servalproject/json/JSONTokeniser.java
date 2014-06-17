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

import java.lang.StringBuilder;
import java.lang.NumberFormatException;
import java.io.IOException;
import java.io.Reader;
import java.io.PushbackReader;
import java.util.Collection;

public class JSONTokeniser {
	
	PushbackReader reader;
	Object pushedToken;

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
	}

	public static class UnexpectedException extends JSONInputException
	{
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
		public UnexpectedTokenException(Object got, Class expecting) {
			super(jsonTokenDescription(got), expecting);
		}

		public UnexpectedTokenException(Object got, Object expecting) {
			super(jsonTokenDescription(got), expecting);
		}

	}

	// Can accept any PushbackReader, because we only need one character of unread().
	public JSONTokeniser(PushbackReader pbrd)
	{
		reader = pbrd;
	}

	public JSONTokeniser(Reader rd)
	{
		reader = new PushbackReader(rd);
	}

	private int _read() throws IOException
	{
		int n = this.reader.read();
		if (DUMP_JSON_TO_STDERR && n != -1)
			System.err.print((char)n);
		return n;
	}

	private int _read(char[] buf, int offset, int length) throws IOException
	{
		int n = this.reader.read(buf, offset, length);
		if (DUMP_JSON_TO_STDERR && n != -1)
			System.err.print(new String(buf, offset, n));
		return n;
	}

	public static void match(Object tok, Token exactly) throws SyntaxException
	{
		if (tok != exactly)
			throw new SyntaxException("JSON syntax error: expecting " + exactly + ", got " + jsonTokenDescription(tok));
	}

	public void consume(Token exactly) throws SyntaxException, UnexpectedException, IOException
	{
		match(nextToken(), exactly);
	}

	public enum Narrow {
		NO_NULL,
		ALLOW_NULL
	};

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
		if (opts == Narrow.ALLOW_NULL && (tok == null || tok == Token.NULL))
			return null;
		if (tok instanceof Token)
			throw new UnexpectedTokenException(tok, cls);
		// Convert:
		// 		Integer --> Float or Double
		// 		Float --> Double
		// 		Double --> Float
		if (cls == Double.class && (tok instanceof Float || tok instanceof Integer))
			tok = new Double(((Number)tok).doubleValue());
		else if (cls == Float.class && (tok instanceof Double || tok instanceof Integer))
			tok = new Float(((Number)tok).floatValue());
		if (cls.isInstance(tok))
			return (T)tok; // unchecked cast
		throw new UnexpectedTokenException(tok, cls);
	}

	public <T> T consume(Class<T> cls) throws SyntaxException, UnexpectedException, IOException
	{
		return consume(cls, Narrow.NO_NULL);
	}

	public <T> T consume(Class<T> cls, Narrow opts) throws SyntaxException, UnexpectedException, IOException
	{
		return narrow(nextToken(), cls, opts);
	}

	public Object consume() throws SyntaxException, UnexpectedException, IOException
	{
		return consume(Object.class, Narrow.NO_NULL);
	}

	public Object consume(Narrow opts) throws SyntaxException, UnexpectedException, IOException
	{
		return consume(Object.class, opts);
	}

	public String consume(String exactly) throws SyntaxException, UnexpectedException, IOException
	{
		String tok = consume(String.class);
		if (tok.equals(exactly))
			return tok;
		throw new UnexpectedTokenException(tok, exactly);
	}

	public int consumeArray(Collection<Object> collection, Narrow opts) throws SyntaxException, UnexpectedException, IOException
	{
		return consumeArray(collection, Object.class, opts);
	}

	public <T> int consumeArray(Collection<T> collection, Class<T> cls) throws SyntaxException, UnexpectedException, IOException
	{
		return consumeArray(collection, cls, Narrow.NO_NULL);
	}

	public <T> int consumeArray(Collection<T> collection, Class<T> cls, Narrow opts) throws SyntaxException, UnexpectedException, IOException
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

	public void consumeArray(Object[] array) throws SyntaxException, UnexpectedException, IOException
	{
		consumeArray(array, Object.class, Narrow.NO_NULL);
	}

	public void consumeArray(Object[] array, Narrow opts) throws SyntaxException, UnexpectedException, IOException
	{
		consumeArray(array, Object.class, opts);
	}

	public <T> void consumeArray(T[] array, Class<T> cls, Narrow opts) throws SyntaxException, UnexpectedException, IOException
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
		return tok instanceof Token || tok instanceof String || tok instanceof Double || tok instanceof Integer || tok instanceof Boolean;
	}

	public static String jsonTokenDescription(Object tok)
	{
		if (tok == null)
			return "null";
		if (tok instanceof String)
			return "\"" + tok + "\"";
		if (tok instanceof Number)
			return "" + tok;
		if (tok instanceof Boolean)
			return "" + tok;
		assert tok instanceof Token;
		return tok.toString();
	}

	private void readWord(String word) throws SyntaxException, IOException
	{
		int len = 0;
		while (len < word.length()) {
			char[] buf = new char[word.length() - len];
			int n = _read(buf, 0, buf.length);
			if (n == -1)
				throw new SyntaxException("EOF in middle of \"" + word + "\"");
			for (int i = 0; i < n; ++i)
				if (buf[i] != word.charAt(len++))
					throw new SyntaxException("expecting \"" + word + "\"");
		}
	}

	private int readHex(int digits) throws SyntaxException, IOException
	{
		char[] buf = new char[digits];
		int len = 0;
		while (len < buf.length) {
			int n = _read(buf, len, buf.length - len);
			if (n == -1)
				throw new SyntaxException("EOF in middle of " + digits + " hex digits");
			len += n;
		}
		String hex = new String(buf);
		try {
			return Integer.valueOf(hex, 16);
		}
		catch (NumberFormatException e) {
			throw new SyntaxException("expecting " + digits + " hex digits, got \"" + hex + "\"");
		}
	}

	public void pushToken(Object tok)
	{
		assert jsonIsToken(tok);
		assert pushedToken == null;
		pushedToken = tok;
	}

	public Object nextToken() throws SyntaxException, IOException
	{
		if (pushedToken != null) {
			Object tok = pushedToken;
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
				this.reader.unread(c);
				readWord("true");
				return Boolean.TRUE;
			case 'f':
				this.reader.unread(c);
				readWord("false");
				return Boolean.FALSE;
			case 'n':
				this.reader.unread(c);
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
					this.reader.unread(c);
					String number = sb.toString();
					try {
						if (isfloat)
							return Double.parseDouble(number);
						else
							return Integer.parseInt(number);
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
		this.reader.close();
	}

}
