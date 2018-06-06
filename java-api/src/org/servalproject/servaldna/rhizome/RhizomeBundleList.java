/**
 * Copyright (C) 2016-2017 Flinders University
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

import org.servalproject.json.JsonObjectHelper;
import org.servalproject.servaldna.BundleId;
import org.servalproject.servaldna.FileHash;
import org.servalproject.servaldna.HttpJsonSerialiser;
import org.servalproject.servaldna.HttpRequest;
import org.servalproject.servaldna.ServalDHttpConnectionFactory;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Vector;

public class RhizomeBundleList extends HttpJsonSerialiser<RhizomeListBundle, IOException> {

	private String sinceToken;
	private String service;
	private String name;
	private SubscriberId sender;
	private SubscriberId recipient;

	public void setServiceFilter(String service){
		this.service = service;
	}
	public void setNameFilter(String name){
		this.name = name;
	}
	public void setSenderFilter(SubscriberId sender){
		this.sender = sender;
	}
	public void setRecipientFilter(SubscriberId recipient){
		this.recipient = recipient;
	}

	public RhizomeBundleList(ServalDHttpConnectionFactory connector)
	{
		this(connector, null);
	}

	public RhizomeBundleList(ServalDHttpConnectionFactory connector, String since_token)
	{
		super(connector);
		addField("id", true, BundleId.class);
		addField("version", true, JsonObjectHelper.LongFactory);
		addField("filesize", true, JsonObjectHelper.LongFactory);
		addField("filehash", false, FileHash.class);
		addField("sender", false, SubscriberId.class);
		addField("recipient", false, SubscriberId.class);
		addField("date", true, JsonObjectHelper.LongFactory);
		addField("service", true, JsonObjectHelper.StringFactory);
		addField("name", false, JsonObjectHelper.StringFactory);
		addField("_id", true, JsonObjectHelper.IntFactory);
		addField(".token", false, JsonObjectHelper.StringFactory);
		addField(".inserttime", true, JsonObjectHelper.LongFactory);
		addField(".author", false, SubscriberId.class);
		addField(".fromhere", true, JsonObjectHelper.IntFactory);
		this.sinceToken = since_token;
	}

	@Override
	protected HttpRequest getRequest() throws UnsupportedEncodingException {
		StringBuilder sb = new StringBuilder();
		if (this.sinceToken == null)
			sb.append("/restful/rhizome/bundlelist.json");
		else if(this.sinceToken.equals(""))
			sb.append("/restful/rhizome/newsince/bundlelist.json");
		else
			sb.append("/restful/rhizome/newsince/").append(this.sinceToken).append("/bundlelist.json");

		Vector<ServalDHttpConnectionFactory.QueryParam> query_params = new Vector<ServalDHttpConnectionFactory.QueryParam>();
		if (service != null)
			query_params.add(new ServalDHttpConnectionFactory.QueryParam("service", service));
		if (name != null)
			query_params.add(new ServalDHttpConnectionFactory.QueryParam("name", name));
		if (sender != null)
			query_params.add(new ServalDHttpConnectionFactory.QueryParam("sender", sender.toHex()));
		if (recipient != null)
			query_params.add(new ServalDHttpConnectionFactory.QueryParam("recipient", recipient.toHex()));

		return new HttpRequest("GET", sb.toString(), query_params);
	}

	@Override
	public RhizomeListBundle create(Object[] parameters, int row) {
		return new RhizomeListBundle(
				new RhizomeManifest((BundleId)parameters[0],
						(Long)parameters[1],
						(Long)parameters[2],
						(FileHash)parameters[3],
						(SubscriberId)parameters[4],
						(SubscriberId)parameters[5],
						null, // BK
						null, // crypt
						null, // tail
						(Long)parameters[6],
						(String)parameters[7],
						(String)parameters[8]),
				row,
				(Integer)parameters[9],
				(String)parameters[10],
				(Long)parameters[11],
				(SubscriberId)parameters[12],
				(Integer)parameters[13]);
	}
}
