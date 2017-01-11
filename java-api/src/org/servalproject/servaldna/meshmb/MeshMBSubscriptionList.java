package org.servalproject.servaldna.meshmb;

import org.servalproject.json.JSONTableScanner;
import org.servalproject.servaldna.AbstractJsonList;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SigningKey;
import org.servalproject.servaldna.Subscriber;

import java.io.IOException;
import java.util.Map;

/**
 * Created by jeremy on 11/01/17.
 */

public class MeshMBSubscriptionList extends AbstractJsonList<MeshMBSubscription, IOException> {

	public final Subscriber identity;

	public MeshMBSubscriptionList(ServalDHttpConnectionFactory httpConnector, Subscriber identity){
		super(httpConnector, new JSONTableScanner()
				.addColumn("id", SigningKey.class)
				.addColumn("name", String.class)
				.addColumn("timestamp", Long.class)
				.addColumn("last_message", String.class)
		);
		this.identity = identity;
	}
	@Override
	protected String getUrl() {
		return "/restful/meshmb/" + identity.signingKey.toHex() + "/feedlist.json";
	}

	@Override
	protected MeshMBSubscription factory(Map<String, Object> row, long rowCount) throws ServalDInterfaceException {
		return new MeshMBSubscription(
				(SigningKey) row.get("id"),
				(String) row.get("name"),
				(Long) row.get("timestamp"),
				(String) row.get("last_message")
		);
	}
}
