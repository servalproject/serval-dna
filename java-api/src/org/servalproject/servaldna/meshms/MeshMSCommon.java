/**
 * Copyright (C) 2016 Flinders University
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

package org.servalproject.servaldna.meshms;

import org.servalproject.servaldna.PostHelper;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;
import java.net.HttpURLConnection;

public class MeshMSCommon
{
	public static final String SERVICE = "MeshMS2";

	public static MeshMSStatus sendMessage(ServalDHttpConnectionFactory connector, SubscriberId sid1, SubscriberId sid2, String text) throws IOException, ServalDInterfaceException, MeshMSException
	{
		MeshMSRequest request = new MeshMSRequest("GET", "/restful/meshms/" + sid1.toHex() + "/" + sid2.toHex() + "/sendmessage");
		try {
			request.setExpectedStatusCodes(HttpURLConnection.HTTP_CREATED);
			PostHelper helper = request.beginPost(connector);
			helper.writeField("message", text);
			helper.close();
			request.checkResponse();
			request.decodeJson();
			return request.meshms_status_code;
		}finally {
			request.close();
		}
	}

	public static MeshMSStatus markAllConversationsRead(ServalDHttpConnectionFactory connector, SubscriberId sid1) throws IOException, ServalDInterfaceException, MeshMSException
	{
		MeshMSRequest request = new MeshMSRequest("POST", "/restful/meshms/" + sid1.toHex() + "/readall");
		try{
			request.setExpectedStatusCodes(HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_CREATED);
			request.connect(connector);
			request.decodeJson();
			return request.meshms_status_code;
		}finally {
			request.close();
		}
	}

	public static MeshMSStatus markAllMessagesRead(ServalDHttpConnectionFactory connector, SubscriberId sid1, SubscriberId sid2) throws IOException, ServalDInterfaceException, MeshMSException
	{
		MeshMSRequest request = new MeshMSRequest("POST", "/restful/meshms/" + sid1.toHex() + "/" + sid2.toHex() + "/readall");
		try{
			request.setExpectedStatusCodes(HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_CREATED);
			request.connect(connector);
			request.decodeJson();
			return request.meshms_status_code;
		}finally {
			request.close();
		}
	}

	public static MeshMSStatus advanceReadOffset(ServalDHttpConnectionFactory connector, SubscriberId sid1, SubscriberId sid2, long offset) throws IOException, ServalDInterfaceException, MeshMSException
	{
		MeshMSRequest request = new MeshMSRequest("POST", "/restful/meshms/" + sid1.toHex() + "/" + sid2.toHex() + "/recv/" + offset + "/read");
		try{
			request.setExpectedStatusCodes(HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_CREATED);
			request.connect(connector);
			request.decodeJson();
			return request.meshms_status_code;
		}finally {
			request.close();
		}
	}
}
