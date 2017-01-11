package org.servalproject.servaldna.meshmb;

import org.servalproject.servaldna.PostHelper;
import org.servalproject.servaldna.ServalDClient;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SigningKey;
import org.servalproject.servaldna.Subscriber;

import java.io.IOException;
import java.net.HttpURLConnection;

/**
 * Created by jeremy on 5/10/16.
 */
public class MeshMBCommon {

    public static final String SERVICE = "MeshMB1";

    public static int sendMessage(ServalDHttpConnectionFactory connector, SigningKey id, String text) throws IOException, ServalDInterfaceException {
        HttpURLConnection conn = connector.newServalDHttpConnection("/restful/meshmb/" + id.toHex() + "/sendmessage");
        PostHelper helper = new PostHelper(conn);
        helper.connect();
        helper.writeField("message", text);
        helper.close();

        // TODO handle specific errors
        return conn.getResponseCode();
    }

    public static int ignore(ServalDHttpConnectionFactory connector, Subscriber id, SigningKey peer) throws ServalDInterfaceException, IOException {
        HttpURLConnection conn = connector.newServalDHttpConnection("/restful/meshmb/" + id.signingKey.toHex() + "/follow/" + peer.toHex());
        conn.setRequestMethod("POST");
        conn.connect();
        return conn.getResponseCode();
    }

    public static int follow(ServalDHttpConnectionFactory connector, Subscriber id, SigningKey peer) throws ServalDInterfaceException, IOException {
        HttpURLConnection conn = connector.newServalDHttpConnection("/restful/meshmb/" + id.signingKey.toHex() + "/ignore/" + peer.toHex());
        conn.setRequestMethod("POST");
        conn.connect();
        return conn.getResponseCode();
    }
}
