package org.servalproject.test;

import org.servalproject.json.JsonParser;

import java.io.IOException;

public class UnitTests{

	public static void main(String... args) {
		if (args.length < 1)
			return;
		String methodName = args[0];
		try {
			if (methodName.equals("json-parser"))
				jsonParser(args[1]);

		}catch (Exception e){
			e.printStackTrace();
			System.exit(1);
		}
		System.err.println("No such command: " + methodName);
		System.exit(1);
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

	private static void jsonParse(int indent, JsonParser parser, JsonParser.ValueType type) throws IOException, JsonParser.JsonParseException {
		String delim;
		switch (type){
			case Null:
				System.out.print("null");
				break;
			case True:
				System.out.print("true");
				break;
			case False:
				System.out.print("false");
				break;
			case String:
				System.out.print(quoteString(parser.readString()));
				break;
			case Number:
				System.out.print(parser.readNumber());
				break;
			case BeginArray:
				System.out.print("[");
				delim = "";
				while((type = parser.nextArrayElement())!=null){
					System.out.print(delim);
					delim = ",";
					jsonParse(indent+1, parser, type);
				}
				System.out.print("]");
				break;
			case BeginObject:
				System.out.print("{");
				delim = "";
				JsonParser.JsonMember member;
				while((member = parser.nextMember())!=null){
					System.out.print(delim);
					delim = ",";
					System.out.print(quoteString(member.name));
					System.out.print(":");
					jsonParse(indent+1, parser, member.type);
				}
				System.out.print("}");
				break;
		}
	}

	private static void jsonParser(String arg) throws IOException, JsonParser.JsonParseException {
		JsonParser parser = (arg.equals("--stdin")) ? new JsonParser(System.in) : new JsonParser(arg);
		jsonParse(0, parser, parser.parse());
		System.exit(0);
	}
}