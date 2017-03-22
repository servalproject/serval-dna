package org.servalproject.servaldna.meshmb;

import org.servalproject.servaldna.Subscriber;

import java.util.Date;

/**
 * Created by jeremy on 21/03/17.
 */

public class MeshMBActivityMessage implements Comparable<MeshMBActivityMessage>{
	public final String token;
	public final long ack_offset;
	public final Subscriber subscriber;
	public final String name;
	public final long offset;
	public final Date date;
	public final long timestamp;
	public final String text;

	public MeshMBActivityMessage(String token,
								 long ack_offset,
								 Subscriber subscriber,
								 String name,
								 long timestamp,
								 long offset,
								 String text){
		this.token = token;
		this.ack_offset = ack_offset;
		this.subscriber = subscriber;
		this.name = name;
		this.offset = offset;
		this.date = new Date(timestamp * 1000);
		this.timestamp = timestamp;
		this.text = text;
	}

	@Override
	public int compareTo(MeshMBActivityMessage message) {
		if (this.ack_offset < message.ack_offset)
			return 1;
		if (this.ack_offset > message.ack_offset)
			return -1;
		if (this.offset < message.offset)
			return 1;
		if (this.offset > message.offset)
			return -1;
		return 0;
	}

}
