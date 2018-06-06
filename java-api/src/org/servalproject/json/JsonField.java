package org.servalproject.json;

import java.util.HashMap;
import java.util.Map;

public class JsonField {
	public final String name;
	public final boolean required;
	public final JsonObjectHelper.Factory factory;

	public JsonField(String name, boolean required, JsonObjectHelper.Factory factory) {
		this.name = name;
		this.required = required;
		this.factory = factory;
	}

	public static MapBuilder mapBuilder(){
		return new MapBuilder();
	}

	public static class MapBuilder {
		private Map<String, JsonField> fields = new HashMap<>();

		public MapBuilder addField(String name, boolean required, Class<?> type){
			fields.put(name, new JsonField(name, required, new JsonObjectHelper.ConstructorFactory(type)));
			return this;
		}

		public MapBuilder addField(String name, boolean required, JsonObjectHelper.Factory factory){
			fields.put(name, new JsonField(name, required, factory));
			return this;
		}

		public Map<String, JsonField> build(){
			return fields;
		}
	}
}
