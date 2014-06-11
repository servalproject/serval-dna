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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLConnection;
import java.net.HttpURLConnection;
import org.servalproject.codec.Base64;
import org.servalproject.servaldna.SubscriberId;
import org.servalproject.servaldna.ServalDCommand;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.meshms.MeshMSConversationList;

public class ServalDClient implements ServalDHttpConnectionFactory
{

	private static final String restfulUsername = "ServalDClient";
	private static final String restfulPasswordDefault = "u6ng^ues%@@SabLEEEE8";
	private static String restfulPassword;
	protected boolean connected;
	int httpPort;

	public static ServalDClient newServalDClient()
	{
		return new ServalDClient();
	}

	protected ServalDClient()
	{
		restfulPassword = null;
		connected = false;
		httpPort = 0;
	}

	private void connect() throws ServalDInterfaceException
	{
		ensureServerRunning();
		if (!connected) {
			if (!fetchRestfulAuthorization())
				createRestfulAuthorization();
			connected = true;
		}
	}

	private void ensureServerRunning() throws ServalDInterfaceException
	{
		ServalDCommand.Status s = ServalDCommand.serverStatus();
		if (!s.status.equals("running"))
			throw new ServalDInterfaceException("server is not running");
		if (s.httpPort < 1 || s.httpPort > 65535)
			throw new ServalDInterfaceException("invalid HTTP port number: " + s.httpPort);
		httpPort = s.httpPort;
	}

	private boolean fetchRestfulAuthorization() throws ServalDInterfaceException
	{
		restfulPassword = ServalDCommand.getConfigItem("rhizome.api.restful.users." + restfulUsername + ".password"); 
		return restfulPassword != null;
	}

	private void createRestfulAuthorization() throws ServalDInterfaceException
	{
		ServalDCommand.setConfigItem("rhizome.api.restful.users." + restfulUsername + ".password", restfulPasswordDefault); 
		ServalDCommand.configSync();
		if (!fetchRestfulAuthorization())
			throw new ServalDInterfaceException("restful password not set");
	}

	public MeshMSConversationList meshmsListConversations(SubscriberId sid) throws ServalDInterfaceException, IOException
	{
		MeshMSConversationList list = new MeshMSConversationList(this, sid);
		list.connect();
		return list;
	}

	// interface ServalDHttpConnectionFactory
	public HttpURLConnection newServalDHttpConnection(String path) throws ServalDInterfaceException, IOException
	{
		connect();
		assert restfulPassword != null;
		assert httpPort != 0;
		URL url = new URL("http", "localhost", httpPort, path);
		URLConnection uconn = url.openConnection();
		HttpURLConnection conn;
		try {
			conn = (HttpURLConnection) uconn;
		}
		catch (ClassCastException e) {
			throw new ServalDInterfaceException("URL.openConnection() returned a " + uconn.getClass().getName() + ", expecting a HttpURLConnection", e);
		}
		int status = 0;
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
