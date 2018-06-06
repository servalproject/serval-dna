package org.servalproject.json;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public abstract class JsonTableSerialiser<T, E extends Exception> {
	protected JsonParser parser;
	protected final List<JsonField> fields = new ArrayList<>();
	protected int rowCount=0;
	private int[] columnMapping;

	public void consumeObject(JsonParser.JsonMember header) throws IOException, JsonParser.JsonParseException {
		parser.skip(header.type);
	}

	protected void addField(String name, boolean required, Class<?> type){
		fields.add(new JsonField(name, required, new JsonObjectHelper.ConstructorFactory(type)));
	}

	protected void addField(String name, boolean required, JsonObjectHelper.Factory factory){
		fields.add(new JsonField(name, required, factory));
	}

	private void parseHeadings() throws JsonParser.JsonParseException, IOException {
		List<Integer> columnMappings = new ArrayList<>();
		Map<String, Integer> mapping = new HashMap<>();
		for(int i=0;i<fields.size();i++)
			mapping.put(fields.get(i).name, i);
		boolean[] found = new boolean[fields.size()];

		while(true) {
			JsonParser.ValueType val = parser.nextArrayElement();
			if (val == null)
				break;
			if (val != JsonParser.ValueType.String)
				parser.expected("string");
			String name = parser.readString();
			Integer index = mapping.get(name);
			if (index == null)
				index = -1;
			else{
				if (found[index])
					parser.error("duplicate heading "+name);
				found[index] = true;
			}
			columnMappings.add(index);
		}

		for(int i=0;i<fields.size();i++){
			JsonField f = fields.get(i);
			if (f.required && !found[i])
				parser.expected(f.name);
		}

		this.columnMapping = new int[columnMappings.size()];
		for(int i=0;i<columnMappings.size();i++)
			this.columnMapping[i] = columnMappings.get(i);
	}

	public void begin(JsonParser parser) throws JsonParser.JsonParseException, IOException {
		this.parser = parser;

		if (parser.parse()!= JsonParser.ValueType.BeginObject)
			parser.expected("object");

		while(true) {
			JsonParser.JsonMember member = parser.nextMember();
			if ("header".equals(member.name)){
				if (member.type!= JsonParser.ValueType.BeginArray)
					parser.expected("array");
				parseHeadings();
				continue;
			}else if("rows".equals(member.name)) {
				if (member.type!= JsonParser.ValueType.BeginArray)
					parser.expected("array");
				if (columnMapping == null)
					parser.expected("header");
				return;
			}
			consumeObject(member);
		}
	}

	public abstract T create(Object[] parameters, int row) throws E;

	public T next() throws IOException, JsonParser.JsonParseException, E {
		JsonParser.ValueType val = parser.nextArrayElement();
		if (val == null) {
			end();
			return null;
		}
		if (val != JsonParser.ValueType.BeginArray)
			parser.expected("array");

		Object[] values = new Object[fields.size()];
		for(int i=0;i<columnMapping.length;i++){
			val = parser.nextArrayElement();
			if (val == null)
				parser.expected("value");
			int index = columnMapping[i];
			if (index<0)
				parser.skip(val);
			else {
				JsonField f = fields.get(index);
				Object value = f.factory.create(parser, val);
				if (f.required && value == null)
					parser.expected(f.name);
				values[index] = value;
			}
		}
		val = parser.nextArrayElement();
		if (val != null)
			parser.expected("end of array");
		T ret = create(values, ++rowCount);
		if (ret == null)
			parser.error("object not created for row");
		return ret;
	}

	private void end() throws IOException, JsonParser.JsonParseException {
		while (true) {
			JsonParser.JsonMember member = parser.nextMember();
			if (member == null)
				break;
			consumeObject(member);
		}
	}
}
