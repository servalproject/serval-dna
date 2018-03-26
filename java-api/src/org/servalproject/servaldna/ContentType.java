package org.servalproject.servaldna;

import java.util.HashMap;
import java.util.Map;

/**
 * Android doesn't include javax.activation.MimeType, so we have to implement it ourselves
 */

public class ContentType {
	public final String type;
	public final String subType;
	public final Map<String,String> parameters;

	// a few common content types to match against
	public static ContentType textPlain = fromConstant("text/plain; charset=utf-8");
	public static ContentType applicationJson = fromConstant("application/json");
	public static ContentType applicationOctetStream = fromConstant("application/octet-stream");

	public class ContentTypeException extends Exception{
		ContentTypeException(String message) {
			super(message);
		}
	}

	public ContentType(String contentType) throws ContentTypeException {
		int delim = contentType.indexOf(';');
		if (delim < 0)
			delim = contentType.length();
		int slash = contentType.indexOf('/');
		if (slash<0 || slash >delim)
			throw new ContentTypeException("Failed to parse "+contentType);
		type = contentType.substring(0,slash).trim().toLowerCase();
		subType = contentType.substring(slash+1,delim).trim().toLowerCase();
		parameters = new HashMap<>();
		while(delim < contentType.length()){
			int eq = contentType.indexOf('=',delim);
			String name = contentType.substring(delim+1,eq).trim().toLowerCase();
			String value;
			if (contentType.charAt(eq+1)=='"'){
				delim = eq+1;
				StringBuilder sb = new StringBuilder();
				while(true){
					if (delim >= contentType.length())
						throw new ContentTypeException("Failed to parse "+contentType);
					char c=contentType.charAt(delim++);
					if (c == '"')
						break;
					if (c == '\\') {
						if (delim >= contentType.length())
							throw new ContentTypeException("Failed to parse "+contentType);
						c = contentType.charAt(delim++);
					}
					sb.append(c);
				}
				value = sb.toString();
				while(delim < contentType.length()){
					char c=contentType.charAt(delim++);
					if (c==';')
						break;
					if (c!=' ')
						throw new ContentTypeException("Failed to parse "+contentType);
				}
			}else{
				delim = contentType.indexOf(';',eq);
				if (delim <0)
					delim = contentType.length();
				value = contentType.substring(eq+1,delim).trim();
			}
			parameters.put(name, value);
		}
	}

	public boolean matches(ContentType other) {
		if (other==null)
			return false;
		if (type.equals(other.type) &&
				(subType.equals(other.subType) || subType.equals("*"))){
			for(Map.Entry<String,String> e: parameters.entrySet()){
				if (!e.getValue().equals(other.parameters.get(e.getKey())))
					return false;
			}
			return true;
		}
		return false;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb
				.append(type)
				.append('/')
				.append(subType);
		if (!parameters.isEmpty()){
			for(Map.Entry<String,String> e: parameters.entrySet()){
				sb
						.append(';')
						.append(e.getKey())
						.append('=');
				String value = e.getValue();
				if (value.indexOf(';')>0 || value.indexOf('"')>0){
					sb
							.append('"')
							.append(value.replace("\"","\\\""))
							.append('"');
				}else{
					sb.append(value);
				}
			}
		}
		return sb.toString();
	}

	public static ContentType fromConstant(String contentType){
		try {
			return new ContentType(contentType);
		} catch (ContentTypeException e) {
			throw new IllegalStateException(e);
		}
	}
}
