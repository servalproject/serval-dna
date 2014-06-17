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

	public static void match(Object tok, Token exactly) throws SyntaxException
	{
		if (tok != exactly)
			throw new SyntaxException("JSON syntax error: expecting " + exactly + ", got " + jsonTokenDescription(tok));
	}

	public void consume(Token exactly) throws SyntaxException, UnexpectedException, IOException
	{
		match(nextToken(), exactly);
	}

	@SuppressWarnings("unchecked")
	public static <T> T narrow(Object tok, Class<T> cls) throws UnexpectedException
	{
		assert !cls.isAssignableFrom(Token.class); // can only narrow to values
		if (tok == Token.EOF)
			throw new UnexpectedEOFException(cls);
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
			return (T)tok;
		throw new UnexpectedTokenException(tok, cls);
	}

	public <T> T consume(Class<T> cls) throws SyntaxException, UnexpectedException, IOException
	{
		return narrow(nextToken(), cls);
	}

	public Object consume() throws SyntaxException, UnexpectedException, IOException
	{
		return consume(Object.class);
	}

	public String consume(String exactly) throws SyntaxException, UnexpectedException, IOException
	{
		String tok = consume(String.class);
		if (tok.equals(exactly))
			return tok;
		throw new UnexpectedTokenException(tok, exactly);
	}

	public <T> int consumeArray(Collection<T> collection, Class<T> cls) throws SyntaxException, UnexpectedException, IOException
	{
		int added = 0;
		consume(Token.START_ARRAY);
		Object tok = nextToken();
		if (tok != Token.END_ARRAY) {
			while (true) {
				collection.add(narrow(tok, cls));
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

	public static boolean jsonIsToken(Object tok)
	{
		return tok instanceof Token || tok instanceof String || tok instanceof Double || tok instanceof Integer || tok instanceof Boolean;
	}

	public static String jsonTokenDescription(Object tok)
	{
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
			int n = this.reader.read(buf, 0, buf.length);
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
			int n = this.reader.read(buf, len, buf.length - len);
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

	public Object nextToken() throws SyntaxException, IOException
	{
		while (true) {
			int c = this.reader.read();
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
						c = this.reader.read();
						if (c == -1)
							throw new SyntaxException("unexpected EOF in JSON string");
						if (slosh) {
							switch (c) {
							case '"': case '/': case '\\': sb.append('"'); break;
							case 'b': sb.append('\b'); break;
							case 'f': sb.append('\f'); break;
							case 'n': sb.append('\n'); break;
							case 'r': sb.append('\r'); break;
							case 't': sb.append('\t'); break;
							case 'u':
								
								int code = readHex(4);
								sb.append((char)code);
								// fall through
							default:
								throw new SyntaxException("malformed JSON string");
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
						c = this.reader.read();
					}
					if (c == '0') {
						sb.append((char)c);
						c = this.reader.read();
					}
					else if (Character.isDigit(c)) {
						do {
							sb.append((char)c);
							c = this.reader.read();
						}
							while (Character.isDigit(c));
					}
					else
						throw new SyntaxException("malformed JSON number");
					boolean isfloat = false;
					if (c == '.') {
						isfloat = true;
						sb.append((char)c);
						c = this.reader.read();
						if (c == -1)
							throw new SyntaxException("unexpected EOF in JSON number");
						if (!Character.isDigit(c))
							throw new SyntaxException("malformed JSON number");
						do {
							sb.append((char)c);
							c = this.reader.read();
						}
							while (Character.isDigit(c));
					}
					if (c == 'e' || c == 'E') {
						isfloat = true;
						sb.append((char)c);
						c = this.reader.read();
						if (c == '+' || c == '-') {
							sb.append((char)c);
							c = this.reader.read();
						}
						if (c == -1)
							throw new SyntaxException("unexpected EOF in JSON number");
						if (!Character.isDigit(c))
							throw new SyntaxException("malformed JSON number");
						do {
							sb.append((char)c);
							c = this.reader.read();
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
