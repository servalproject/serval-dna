package org.servalproject.servaldna.meshmb;

import org.servalproject.json.JSONTableScanner;
import org.servalproject.json.JSONTokeniser;
import org.servalproject.servaldna.AbstractJsonList;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SigningKey;
import org.servalproject.servaldna.Subscriber;
import org.servalproject.servaldna.SubscriberId;

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
				.addColumn("author", SubscriberId.class)
				.addColumn("blocked", Boolean.class)
				.addColumn("name", String.class, JSONTokeniser.Narrow.ALLOW_NULL)
				.addColumn("timestamp", Long.class)
				.addColumn("last_message", String.class, JSONTokeniser.Narrow.ALLOW_NULL)
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
				new Subscriber((SubscriberId)row.get("author"),
						(SigningKey) row.get("id"),
						true),
				(Boolean) row.get("blocked"),
				(String) row.get("name"),
				(Long) row.get("timestamp"),
				(String) row.get("last_message")
		);
	}
}
