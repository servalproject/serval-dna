package org.servalproject.servaldna.meshmb;

import org.servalproject.servaldna.BundleId;
import org.servalproject.servaldna.SigningKey;

/**
 * Created by jeremy on 11/01/17.
 */
public class MeshMBSubscription {
	public final SigningKey id;
	public final String name;
	public final long timestamp;
	public final String lastMessage;

	public MeshMBSubscription(SigningKey id, String name, long timestamp, String lastMessage){
		this.id = id;
		this.name = name;
		this.lastMessage = lastMessage;
		this.timestamp = timestamp;
	}
}
