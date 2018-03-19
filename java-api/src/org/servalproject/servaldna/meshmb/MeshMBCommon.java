/**
 * Copyright (C) 2016-2017 Flinders University
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

package org.servalproject.servaldna.meshmb;

import org.servalproject.servaldna.PostHelper;
import org.servalproject.servaldna.ServalDClient;
import org.servalproject.servaldna.ServalDFailureException;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SigningKey;
import org.servalproject.servaldna.Subscriber;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.Vector;

public class MeshMBCommon {

    public static final String SERVICE = "MeshMB1";

    public enum SubscriptionAction{
        Follow,
        Ignore,
        Block
    }

    public static int sendMessage(ServalDHttpConnectionFactory connector, SigningKey id, String text) throws IOException, ServalDInterfaceException {
        HttpURLConnection conn = connector.newServalDHttpConnection("GET", "/restful/meshmb/" + id.toHex() + "/sendmessage");
        PostHelper helper = new PostHelper(conn);
        helper.connect();
        helper.writeField("message", text);
        helper.close();
        int responseCode = conn.getResponseCode();
        // TODO specific errors
        if (responseCode!=201)
            throw new ServalDFailureException("received unexpected HTTP Status "+
                    conn.getResponseCode()+" " + conn.getResponseMessage()+" from " + conn.getURL());
        return responseCode;
    }

    public static int alterSubscription(ServalDHttpConnectionFactory connector, Subscriber id, SubscriptionAction action, Subscriber peer, String name) throws ServalDInterfaceException, IOException {
        Vector<ServalDHttpConnectionFactory.QueryParam> parms = new Vector<ServalDHttpConnectionFactory.QueryParam>();
        parms.add(new ServalDHttpConnectionFactory.QueryParam("sender", peer.sid.toHex()));
        if (name!=null && !"".equals(name))
            parms.add(new ServalDHttpConnectionFactory.QueryParam("name", name));
        HttpURLConnection conn = connector.newServalDHttpConnection(
				"GET",
                "/restful/meshmb/"+id.signingKey.toHex()+"/"+action.toString().toLowerCase()+"/"+peer.signingKey.toHex(),
                parms
        );
        conn.setRequestMethod("POST");
        conn.connect();
        int responseCode = conn.getResponseCode();
        // TODO specific errors
        if (responseCode!=201)
            throw new ServalDFailureException("received unexpected HTTP Status "+
                    conn.getResponseCode()+" " + conn.getResponseMessage()+" from " + conn.getURL());
        return responseCode;
    }
}
