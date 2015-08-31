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

package org.servalproject.servaldna;

import java.lang.Iterable;
import java.lang.StringBuilder;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;

public interface ServalDHttpConnectionFactory {

	public static class QueryParam
	{
		public final String key;
		public final String value;
		public QueryParam(String key, String value) {
			this.key = key;
			this.value = value;
		}

		public void uri_encode(StringBuilder str) throws UnsupportedEncodingException {
			uri_encode_string(str, this.key);
			if (this.value != null) {
				str.append('=');
				uri_encode_string(str, this.value);
			}
		}

		static private void uri_encode_string(StringBuilder str, String text) throws UnsupportedEncodingException {
			for (byte b : text.getBytes("UTF-8")) {
				if (	(b >= '0' && b <= '9')
					||	(b >= 'A' && b <= 'Z')
					||	(b >= 'a' && b <= 'z')
					||  b == '_' || b == '.' || b == '-' || b == '~') {
					str.appendCodePoint(b);
				} else {
					str.append('%');
					str.append(Character.forDigit((b >> 4) % 16, 16));
					str.append(Character.forDigit(b % 16, 16));
				}
			}
		}
	}

	public HttpURLConnection newServalDHttpConnection(String path) throws ServalDInterfaceException, IOException;

	public HttpURLConnection newServalDHttpConnection(String path, Iterable<QueryParam> query_params) throws ServalDInterfaceException, IOException;

}
