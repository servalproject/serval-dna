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

import org.servalproject.json.JSONTableScanner;
import org.servalproject.json.JSONTokeniser;
import org.servalproject.servaldna.AbstractJsonList;
import org.servalproject.servaldna.BundleId;
import org.servalproject.servaldna.FileHash;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;
import java.util.Map;

public class RhizomeBundleList extends AbstractJsonList<RhizomeListBundle, IOException> {

	private String sinceToken;
	private String service;
	private String name;

	public RhizomeBundleList(ServalDHttpConnectionFactory connector)
	{
		this(connector, null);
	}

	public void setServiceFilter(String service){
		this.service = service;
	}
	public void setNameFilter(String name){
		this.name = name;
	}

	public RhizomeBundleList(ServalDHttpConnectionFactory connector, String since_token)
	{
		super(connector, new JSONTableScanner()
				.addColumn("_id", Integer.class)
				.addColumn(".token", String.class, JSONTokeniser.Narrow.ALLOW_NULL)
				.addColumn("service", String.class)
				.addColumn("id", BundleId.class)
				.addColumn("version", Long.class)
				.addColumn("date", Long.class)
				.addColumn(".inserttime", Long.class)
				.addColumn(".author", SubscriberId.class, JSONTokeniser.Narrow.ALLOW_NULL)
				.addColumn(".fromhere", Integer.class)
				.addColumn("filesize", Long.class)
				.addColumn("filehash", FileHash.class, JSONTokeniser.Narrow.ALLOW_NULL)
				.addColumn("sender", SubscriberId.class, JSONTokeniser.Narrow.ALLOW_NULL)
				.addColumn("recipient", SubscriberId.class, JSONTokeniser.Narrow.ALLOW_NULL)
				.addColumn("name", String.class, JSONTokeniser.Narrow.ALLOW_NULL));
		this.sinceToken = since_token;
	}

	@Override
	protected String getUrl() {
		String url;
		if (this.sinceToken == null)
			url = "/restful/rhizome/bundlelist.json";
		else if(this.sinceToken.equals(""))
			url = "/restful/rhizome/newsince/bundlelist.json";
		else
			url = "/restful/rhizome/newsince/" + this.sinceToken + "/bundlelist.json";
		String parms="";
		if (service != null)
			parms += "service="+service;
		if (name!=null) {
			if (!"".equals(parms))
				parms+="&";
			parms += "name=" + name;
		}
		if (!"".equals(parms))
			url+="?"+parms;
		return url;
	}

	@Override
	protected RhizomeListBundle factory(Map<String, Object> row, long rowCount) throws ServalDInterfaceException {
		return new RhizomeListBundle(
				new RhizomeManifest((BundleId)row.get("id"),
						(Long)row.get("version"),
						(Long)row.get("filesize"),
						(FileHash)row.get("filehash"),
						(SubscriberId)row.get("sender"),
						(SubscriberId)row.get("recipient"),
						null, // BK
						null, // crypt
						null, // tail
						(Long)row.get("date"),
						(String)row.get("service"),
						(String)row.get("name")),
				(int)rowCount,
				(Integer)row.get("_id"),
				(String)row.get(".token"),
				(Long)row.get(".inserttime"),
				(SubscriberId)row.get(".author"),
				(Integer)row.get(".fromhere")
		);
	}

	@Deprecated
	public RhizomeListBundle nextBundle() throws ServalDInterfaceException, IOException
	{
		return next();
	}
}
