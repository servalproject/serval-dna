/**
 * Copyright (C) 2014 Serval Project Inc.
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

package org.servalproject.servaldna.rhizome;

import org.servalproject.servaldna.BundleId;
import org.servalproject.servaldna.SubscriberId;
import org.servalproject.servaldna.FileHash;

public class RhizomeBundle {

	public final int _rowNumber;
	public final int _id;
	public final String _token;
	public final String service;
	public final BundleId id;
	public final long version;
	public final long date;
	public final long _inserttime;
	public final SubscriberId _author;
	public final int _fromhere;
	public final long filesize;
	public final FileHash filehash;
	public final SubscriberId sender;
	public final SubscriberId recipient;
	public final String name;

	protected RhizomeBundle(int rowNumber,
							int _id,
							String _token,
							String service,
							BundleId id, 
							long version,
							long date,
							long _inserttime,
							SubscriberId _author,
							int _fromhere,
							long filesize,
							FileHash filehash,
							SubscriberId sender,
							SubscriberId recipient,
							String name)
	{
		this._rowNumber = rowNumber;
		this._id = _id;
		this._token = _token;
		this.service = service;
		this.id = id;
		this.version = version;
		this.date = date;
		this._inserttime = _inserttime;
		this._author = _author;
		this._fromhere = _fromhere;
		this.filesize = filesize;
		this.filehash = filehash;
		this.sender = sender;
		this.recipient = recipient;
		this.name = name;
	}

}
