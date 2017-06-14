package org.servalproject.servaldna.meshmb;

import org.servalproject.servaldna.PostHelper;
import org.servalproject.servaldna.ServalDClient;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SigningKey;
import org.servalproject.servaldna.Subscriber;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.Vector;

/**
 * Created by jeremy on 5/10/16.
 */
public class MeshMBCommon {

    public static final String SERVICE = "MeshMB1";

    public enum SubscriptionAction{
        Follow,
        Ignore,
        Block
    }

    public static int sendMessage(ServalDHttpConnectionFactory connector, SigningKey id, String text) throws IOException, ServalDInterfaceException {
        HttpURLConnection conn = connector.newServalDHttpConnection("/restful/meshmb/" + id.toHex() + "/sendmessage");
        PostHelper helper = new PostHelper(conn);
        helper.connect();
        helper.writeField("message", text);
        helper.close();

        // TODO handle specific errors
        return conn.getResponseCode();
    }

    public static int alterSubscription(ServalDHttpConnectionFactory connector, Subscriber id, SubscriptionAction action, Subscriber peer, String name) throws ServalDInterfaceException, IOException {
        Vector<ServalDHttpConnectionFactory.QueryParam> parms = new Vector<>();
        parms.add(new ServalDHttpConnectionFactory.QueryParam("sender", peer.sid.toHex()));
        if (name!=null && !"".equals(name))
            parms.add(new ServalDHttpConnectionFactory.QueryParam("name", name));
        HttpURLConnection conn = connector.newServalDHttpConnection(
                "/restful/meshmb/"+id.signingKey.toHex()+"/"+peer.signingKey.toHex(),
                parms
        );
        conn.setRequestMethod("POST");
        conn.connect();
        return conn.getResponseCode();
    }
}
