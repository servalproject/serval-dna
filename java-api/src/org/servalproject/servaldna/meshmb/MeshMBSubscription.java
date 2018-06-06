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

public class MeshMBSubscription {
	public final Subscriber subscriber;
	public final boolean blocked;
	public final String name;
	public final long timestamp;
	public final String lastMessage;

	public MeshMBSubscription(Subscriber subscriber, boolean blocked, String name, long timestamp, String lastMessage){
		this.blocked = blocked;
		this.subscriber = subscriber;
		this.name = name;
		this.lastMessage = lastMessage;
		this.timestamp = timestamp;
	}
}
