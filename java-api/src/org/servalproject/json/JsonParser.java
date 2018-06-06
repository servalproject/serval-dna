package org.servalproject.json;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.nio.CharBuffer;
import java.util.Stack;

public class JsonParser {

	public class JsonParseException extends JSONInputException{
		public JsonParseException(String message) {
			super(message);
		}

		public JsonParseException(String message, Throwable e) {
			super(message, e);
		}
	}

	private final Reader reader;
	private final CharBuffer buff;
	private boolean eof = false;
	private int current = 0;
	private int line=1;
	private int column=0;
	private boolean firstElement = true;

	public static class JsonMember{
		public final String name;
		public final ValueType type;

		private JsonMember(String name, ValueType type) {
			this.name = name;
			this.type = type;
		}
	}

	public enum ValueType{
		Null,
		True,
		False,
		Number,
		String,
		BeginArray,
		BeginObject
	}

	private Stack<ValueType> stack = new Stack<>();

	public JsonParser(InputStream stream) throws IOException {
		this(new InputStreamReader(stream, "UTF-8"));
	}

	public JsonParser(Reader reader) {
		this.reader = reader;
		buff = CharBuffer.allocate(16*1024);
		buff.flip();
	}

	public JsonParser(String json){
		this(new StringReader(json));
	}

	public void error(String error) throws JsonParseException {
		throw new JsonParseException(error+" at "+line+":"+column);
	}

	public void error(String error, Throwable e) throws JsonParseException {
		throw new JsonParseException(error+" at "+line+":"+column, e);
	}

	public void expected(String expected) throws JsonParseException{
		if (isEof())
			error("Expected "+expected+", got end of input");
		error("Expected "+expected+", got '"+((char)current)+"'");
	}

	public void expected(String expected, Throwable e) throws JsonParseException{
		if (isEof())
			error("Expected "+expected+", got end of input", e);
		error("Expected "+expected+", got '"+((char)current)+"'", e);
	}

	private int read() throws IOException {
		if (!buff.hasRemaining()){
			if (eof)
				return (current = -1);
			buff.clear();
			int r = reader.read(buff);

			eof = (r == -1);
			if (eof)
				return (current = -1);
			buff.flip();
		}
		current = buff.get();
		if (current == '\n'){
			line++;
			column=0;
		}
		column++;
		return current;
	}

	private boolean readChar(char ch) throws IOException {
		if (current == 0)
			read();
		if (current != ch) {
			return false;
		}
		read();
		return true;
	}

	private void requireChar(char ch) throws IOException, JsonParseException {
		if (!readChar(ch))
			expected("'"+ch+"'");
	}

	private void requireConstString(String str) throws IOException, JsonParseException{
		// Check for every character, without attempting to read past the end
		for(int i=0;i<str.length();i++) {
			if (current == 0)
				read();
			char ch = str.charAt(i);
			if (current != ch)
				expected("'"+ch+"'");
			current = 0;
		}
	}

	private void skipWhiteSpace() throws IOException {
		if (current == 0)
			read();
		while(isWhiteSpace())
			read();
	}

	private boolean isEof(){
		return current == -1;
	}

	private boolean isWhiteSpace() {
		return current == ' ' || current == '\t' || current == '\n' || current == '\r';
	}

	private boolean isDigit() {
		return current >= '0' && current <= '9';
	}

	private boolean isHexDigit() {
		return current >= '0' && current <= '9'
				|| current >= 'a' && current <= 'f'
				|| current >= 'A' && current <= 'F';
	}

	public ValueType parse() throws IOException, JsonParseException{
		if (!stack.isEmpty() || !firstElement)
			error("Already parsing");
		ValueType ret = next();
		switch (ret){
			case Null:
			case True:
			case False:
				skipWhiteSpace();
				if (!isEof())
					expected("end of input");
		}
		return ret;
	}

	private ValueType next() throws IOException, JsonParseException {
		if (current == 0)
			skipWhiteSpace();

		if (firstElement)
			firstElement = false;

		switch (current){
			case 'n':
				requireConstString("null");
				return ValueType.Null;
			case 't':
				requireConstString("true");
				return ValueType.True;
			case 'f':
				requireConstString("false");
				return ValueType.False;
			case '"':
				return ValueType.String;
			case '[':
				stack.push(ValueType.BeginArray);
				firstElement = true;
				return ValueType.BeginArray;
			case '{':
				stack.push(ValueType.BeginObject);
				firstElement = true;
				return ValueType.BeginObject;
			case '-':
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
				return ValueType.Number;
		}
		expected("value");
		throw new UnsupportedOperationException("Unreachable");
	}

	public Object asObject(ValueType type) throws IOException, JsonParseException {
		switch (type){
			case Null:
				return null;
			case True:
				return true;
			case False:
				return false;
			case String:
				return readString();
			case Number:
				return readNumber();
		}
		expected("value");
		throw new UnsupportedOperationException("unreachable");
	}

	public JsonMember nextMember() throws IOException, JsonParseException {
		if (stack.isEmpty() || stack.peek() != ValueType.BeginObject)
			error("Not in an object");

		if (firstElement)
			requireChar('{');
		skipWhiteSpace();

		if (current == '}'){
			// don't block on a read after '}'
			current = 0;
			stack.pop();
			firstElement = false;

			if (stack.isEmpty()){
				skipWhiteSpace();
				if (!isEof())
					expected("end of input");
			}

			return null;
		}

		if (!firstElement) {
			if (!readChar(','))
				expected("',' or '}'");
			else
				skipWhiteSpace();
		}

		String name = readString();
		skipWhiteSpace();
		requireChar(':');
		skipWhiteSpace();
		return new JsonMember(name, next());
	}

	public ValueType nextArrayElement() throws IOException, JsonParseException {
		if (stack.isEmpty() || stack.peek() != ValueType.BeginArray)
			error("Not in an array");

		if (firstElement)
			requireChar('[');
		skipWhiteSpace();

		if (current == ']') {
			// don't block on a read after ']'
			current = 0;
			stack.pop();
			firstElement = false;

			if (stack.isEmpty()){
				skipWhiteSpace();
				if (!isEof())
					expected("end of input");
			}

			return null;
		}

		if (!firstElement) {
			if (!readChar(','))
				expected("',' or ']'");
			else
				skipWhiteSpace();
		}

		return next();
	}

	public void skip(ValueType type) throws IOException, JsonParseException {
		if (type == null)
			return;

		switch (type){
			case String:
				readString();
				return;
			case Number:
				readNumber();
				return;
			case BeginArray:
				while(true){
					ValueType element = nextArrayElement();
					if (element == null)
						return;
					skip(element);
				}
			case BeginObject:
				while(true){
					JsonMember member = nextMember();
					if (member == null)
						return;
					skip(member.type);
				}
		}
	}

	public Number readNumber() throws IOException, JsonParseException {
		StringBuilder sb = new StringBuilder();
		boolean isDouble = false;
		if (current=='-'){
			sb.append((char)current);
			read();
		}
		if (current=='0') {
			sb.append((char)current);
			read();
		} else {
			if (!isDigit())
				expected("digit");
			do{
				sb.append((char)current);
				read();
			}while(isDigit());
		}
		if (current=='.'){
			isDouble = true;
			sb.append((char)current);
			read();
			if (!isDigit())
				expected("digit");
			do{
				sb.append((char)current);
				read();
			}while(isDigit());
		}
		if (current=='e' || current=='E'){
			isDouble = true;
			sb.append((char)current);
			read();
			if (current == '+' || current == '-'){
				sb.append((char)current);
				read();
			}
			if (!isDigit())
				expected("digit");
			do{
				sb.append((char)current);
				read();
			}while(isDigit());
		}

		String number = sb.toString();
		Number ret;
		try{
			if (isDouble){
				ret = Double.parseDouble(number);
			}else{
				long l = Long.parseLong(number);
				if (l>=Integer.MIN_VALUE && l<=Integer.MAX_VALUE)
					ret = (int)l;
				else
					ret = l;
			}
		}catch (NumberFormatException e){
			expected("number",e);
			throw new UnsupportedOperationException("unreachable");
		}

		if (stack.isEmpty()){
			skipWhiteSpace();
			if (!isEof())
				expected("end of input");
		}
		return ret;
	}

	public String readString() throws IOException, JsonParseException {
		StringBuilder sb = new StringBuilder();
		requireChar('"');
		while(current != '"'){
			if (current == '\\'){
				switch (read()) {
					case 'b':
						sb.append('\b');
						break;
					case 'f':
						sb.append('\f');
						break;
					case 'r':
						sb.append('\r');
						break;
					case 'n':
						sb.append('\n');
						break;
					case 't':
						sb.append('\t');
						break;
					case 'u':
						int val=0;
						for(int i=0;i<4;i++){
							read();
							if (!isHexDigit())
								expected("hexadecimal");
							val = Character.digit((char)current,16) | (val<<4);
						}
						sb.append((char)val);
						break;
					case '"':
					case '\\':
					case '/':
						sb.append((char)current);
						break;
					default:
						expected("escape sequence");
				}
			}else
				sb.append((char)current);
			read();
		}
		current=0;
		if (stack.isEmpty()){
			skipWhiteSpace();
			if (!isEof())
				expected("end of input");
		}
		return sb.toString();
	}
}
