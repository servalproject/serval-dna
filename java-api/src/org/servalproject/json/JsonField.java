package org.servalproject.json;

public class JsonField {
	public final String name;
	public final boolean required;
	public final JsonObjectHelper.Factory factory;

	public JsonField(String name, boolean required, JsonObjectHelper.Factory factory) {
		this.name = name;
		this.required = required;
		this.factory = factory;
	}
}
