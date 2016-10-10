package org.servalproject.servaldna.meshmb;

import org.servalproject.json.JSONTableScanner;
import org.servalproject.json.JSONTokeniser;
import org.servalproject.servaldna.AbstractJsonList;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SigningKey;

import java.io.IOException;
import java.util.Map;

/**
 * Created by jeremy on 10/10/16.
 */
public class MessagePlyList extends AbstractJsonList<PlyMessage, IOException> {
    private final SigningKey bundleId;
    private final String sinceToken;

    public MessagePlyList(ServalDHttpConnectionFactory httpConnector, SigningKey bundleId, String sinceToken){
        super(httpConnector, new JSONTableScanner()
                .addColumn("offset", Long.class)
                .addColumn("token", String.class)
                .addColumn("text", String.class)
                .addColumn("timestamp", Long.class, JSONTokeniser.Narrow.ALLOW_NULL));
        this.bundleId = bundleId;
        this.sinceToken = sinceToken;
    }

    @Override
    protected void handleResponseError() throws IOException, ServalDInterfaceException {
        // TODO handle specific errors
        super.handleResponseError();
    }

    @Override
    protected String getUrl() {
        if (this.sinceToken == null)
            return "/restful/meshmb/" + bundleId.toHex() + "/messagelist.json";
        else if(this.sinceToken.equals(""))
            return "/restful/meshmb/" + bundleId.toHex() + "/newsince/messagelist.json";
        else
            return "/restful/meshmb/" + bundleId.toHex() + "/newsince/" + sinceToken + "/messagelist.json";
    }

    @Override
    protected PlyMessage factory(Map<String, Object> row, long rowCount) {
        return new PlyMessage(
                rowCount,
                (Long)row.get("offset"),
                (String)row.get("token"),
                (Long)row.get("timestamp"),
                (String)row.get("text")
        );
    }
}
