package org.servalproject.servaldna.rhizome;

import org.servalproject.servaldna.SubscriberId;

public class RhizomeSyncStatus {
	public final SubscriberId sid;
	public final long receivedBundles;
	public final long sentBytes;
	public final long sendingBytes;
	public final long receivedBytes;
	public final long requestedBytes;

	public RhizomeSyncStatus(SubscriberId sid,
							 long receivedBundles,
							 long sentBytes,
							 long sendingBytes,
							 long receivedBytes,
							 long requestedBytes) {
		this.sid = sid;
		this.receivedBundles = receivedBundles;
		this.sentBytes = sentBytes;
		this.sendingBytes = sendingBytes;
		this.receivedBytes = receivedBytes;
		this.requestedBytes = requestedBytes;
	}
}
