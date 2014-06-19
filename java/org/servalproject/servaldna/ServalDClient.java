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

import org.servalproject.codec.Base64;
import org.servalproject.servaldna.meshms.MeshMSConversationList;
import org.servalproject.servaldna.meshms.MeshMSException;
import org.servalproject.servaldna.meshms.MeshMSMessageList;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLConnection;
import java.net.HttpURLConnection;
import org.servalproject.codec.Base64;
import org.servalproject.servaldna.SubscriberId;
import org.servalproject.servaldna.ServalDCommand;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.meshms.MeshMSCommon;
import org.servalproject.servaldna.meshms.MeshMSConversationList;
import org.servalproject.servaldna.meshms.MeshMSMessageList;
import org.servalproject.servaldna.meshms.MeshMSException;
import org.servalproject.servaldna.meshms.MeshMSStatus;

public class ServalDClient implements ServalDHttpConnectionFactory
{
	private final int httpPort;
	private final String restfulUsername;
	private final String restfulPassword;

	public ServalDClient(int httpPort, String restfulUsername, String restfulPassword) throws ServalDInterfaceException {
		if (httpPort < 1 || httpPort > 65535)
			throw new ServalDInterfaceException("invalid HTTP port number: " + httpPort);
		if (restfulUsername == null)
			throw new ServalDInterfaceException("invalid HTTP username");
		if (restfulPassword == null)
			throw new ServalDInterfaceException("invalid HTTP password");
		this.httpPort = httpPort;
		this.restfulUsername = restfulUsername;
		this.restfulPassword = restfulPassword;
	}

	public MeshMSConversationList meshmsListConversations(SubscriberId sid) throws ServalDInterfaceException, IOException, MeshMSException
	{
		MeshMSConversationList list = new MeshMSConversationList(this, sid);
		list.connect();
		return list;
	}

	public MeshMSMessageList meshmsListMessages(SubscriberId sid1, SubscriberId sid2) throws IOException, ServalDInterfaceException, MeshMSException
	{
		MeshMSMessageList list = new MeshMSMessageList(this, sid1, sid2);
		list.connect();
		return list;
	}

	public MeshMSStatus meshmsSendMessage(SubscriberId sid1, SubscriberId sid2, String text) throws IOException, ServalDInterfaceException, MeshMSException
	{
		return MeshMSCommon.sendMessage(this, sid1, sid2, text);
	}

	// interface ServalDHttpConnectionFactory
	public HttpURLConnection newServalDHttpConnection(String path) throws ServalDInterfaceException, IOException
	{
		URL url = new URL("http", "localhost", httpPort, path);
		URLConnection uconn = url.openConnection();
		HttpURLConnection conn;
		try {
			conn = (HttpURLConnection) uconn;
		}
		catch (ClassCastException e) {
			throw new ServalDInterfaceException("URL.openConnection() returned a " + uconn.getClass().getName() + ", expecting a HttpURLConnection", e);
		}
		conn.setAllowUserInteraction(false);
		try {
			conn.addRequestProperty("Authorization", "Basic " + Base64.encode((restfulUsername + ":" + restfulPassword).getBytes("US-ASCII")));
		}
		catch (UnsupportedEncodingException e) {
			throw new ServalDInterfaceException("invalid RESTful password", e);
		}
		return conn;
	}

}
