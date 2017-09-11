/**
 * Copyright (C) 2017 Flinders University
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

import org.servalproject.servaldna.Subscriber;

import java.util.Date;

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
