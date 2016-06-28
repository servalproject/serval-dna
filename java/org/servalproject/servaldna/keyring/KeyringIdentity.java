/**
 * Copyright (C) 2015 Serval Project Inc.
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

package org.servalproject.servaldna.keyring;

import org.servalproject.servaldna.Subscriber;
import org.servalproject.servaldna.SubscriberId;

public class KeyringIdentity {

	public final int rowNumber;
	public final Subscriber subscriber;
	@Deprecated
	public final SubscriberId sid;
	public final String did;
	public final String name;

	protected KeyringIdentity(int rowNumber,
							  Subscriber subscriber,
							  String did,
							  String name)
	{
		this.rowNumber = rowNumber;
		this.subscriber = subscriber;
		this.sid = subscriber.sid;
		this.did = did;
		this.name = name;
	}

}
