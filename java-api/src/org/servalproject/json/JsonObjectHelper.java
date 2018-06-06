package org.servalproject.json;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;

public class JsonObjectHelper {

	public interface Factory {
		Object create(JsonParser parser, JsonParser.ValueType type) throws IOException, JsonParser.JsonParseException;
	}

	public static Factory StringFactory = new Factory() {
		@Override
		public Object create(JsonParser parser, JsonParser.ValueType type) throws IOException, JsonParser.JsonParseException {
			if (type == JsonParser.ValueType.Null)
				return null;
			return parser.readString();
		}
	};

	public static Factory BoolFactory = new Factory() {
		@Override
		public Object create(JsonParser parser, JsonParser.ValueType type) throws IOException, JsonParser.JsonParseException {
			switch (type){
				case Null:
					return null;
				case True:
					return true;
				case False:
					return false;
			}
			parser.expected("boolean");
			throw new UnsupportedOperationException("unreachable");
		}
	};

	public static Factory LongFactory = new Factory() {
		@Override
		public Object create(JsonParser parser, JsonParser.ValueType type) throws IOException, JsonParser.JsonParseException {
			if (type == JsonParser.ValueType.Null)
				return null;
			return parser.readNumber().longValue();
		}
	};

	public static Factory IntFactory = new Factory() {
		@Override
		public Object create(JsonParser parser, JsonParser.ValueType type) throws IOException, JsonParser.JsonParseException {
			if (type == JsonParser.ValueType.Null)
				return null;
			return parser.readNumber().intValue();
		}
	};

	public static Factory DoubleFactory = new Factory() {
		@Override
		public Object create(JsonParser parser, JsonParser.ValueType type) throws IOException, JsonParser.JsonParseException {
			if (type == JsonParser.ValueType.Null)
				return null;
			return parser.readNumber().doubleValue();
		}
	};

	public static class ConstructorFactory implements Factory{
		private final Class<?> type;
		public ConstructorFactory(Class<?> type){
			this.type = type;
		}

		@Override
		public Object create(JsonParser parser, JsonParser.ValueType type) throws IOException, JsonParser.JsonParseException {
			Object value = parser.asObject(type);
			if (value == null)
				return null;
			try {
				return this.type.getConstructor(value.getClass()).newInstance(value);
			} catch (InvocationTargetException e) {
				Throwable t = e.getTargetException();
				parser.error(t.getMessage(), t);
			} catch (Exception e) {
				parser.error(e.getMessage(), e);
			}
			throw new UnsupportedOperationException("unreachable");
		}
	}

	public abstract static class ObjectFactory<T> implements Factory{
		protected final Map<String, JsonField> columnMap = new HashMap<>();

		protected void add(String name, boolean required, Factory factory){
			columnMap.put(name, new JsonField(name, required, factory));
		}

		@Override
		public Object create(JsonParser parser, JsonParser.ValueType type) throws IOException, JsonParser.JsonParseException {
			if (type == JsonParser.ValueType.Null)
				return null;

			if (type != JsonParser.ValueType.BeginObject)
				parser.expected("object");

			return create(mapObject(parser, columnMap));
		}

		public abstract T create(Map<String, Object> row);
	}

	public static Map<String, Object> mapArray(JsonParser parser, Map<String, JsonField> definition, String[] columns) throws IOException, JsonParser.JsonParseException {
		Map<String, Object> row = new HashMap<>();
		for (int i=0;i<columns.length;i++) {
			JsonParser.ValueType val = parser.nextArrayElement();
			if (val == null)
				parser.expected("value");

			JsonField col = definition.get(columns[i]);
			if (col == null){
				parser.skip(val);
				continue;
			}
			Object value = col.factory.create(parser, val);
			if (col.required && value == null)
				parser.expected("value");
			row.put(col.name, value);
		}
		if (parser.nextArrayElement()!=null)
			parser.expected("array end");
		return row;
	}

	public static Map<String, Object> mapObject(JsonParser parser, Map<String, JsonField> definition) throws IOException, JsonParser.JsonParseException {
		Map<String, Object> row = new HashMap<>();

		while(true){
			JsonParser.JsonMember member = parser.nextMember();
			if (member == null)
				break;
			JsonField col = definition.get(member.name);
			if (col == null){
				parser.skip(member.type);
				continue;
			}
			Object value = col.factory.create(parser, member.type);
			if (col.required && value == null)
				parser.expected("value");
			row.put(col.name, value);
		}

		for(JsonField c : definition.values()){
			if (c.required && !row.containsKey(c.name))
				parser.expected(c.name);
		}

		return row;
	}
}
