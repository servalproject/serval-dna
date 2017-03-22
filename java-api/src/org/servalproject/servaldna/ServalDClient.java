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

package org.servalproject.servaldna;

import org.servalproject.codec.Base64;
import org.servalproject.servaldna.keyring.KeyringCommon;
import org.servalproject.servaldna.keyring.KeyringIdentity;
import org.servalproject.servaldna.keyring.KeyringIdentityList;
import org.servalproject.servaldna.meshmb.MeshMBActivityList;
import org.servalproject.servaldna.meshmb.MeshMBCommon;
import org.servalproject.servaldna.meshmb.MeshMBSubscriptionList;
import org.servalproject.servaldna.meshmb.MessagePlyList;
import org.servalproject.servaldna.meshms.MeshMSCommon;
import org.servalproject.servaldna.meshms.MeshMSConversationList;
import org.servalproject.servaldna.meshms.MeshMSException;
import org.servalproject.servaldna.meshms.MeshMSMessageList;
import org.servalproject.servaldna.meshms.MeshMSStatus;
import org.servalproject.servaldna.rhizome.RhizomeBundleList;
import org.servalproject.servaldna.rhizome.RhizomeCommon;
import org.servalproject.servaldna.rhizome.RhizomeDecryptionException;
import org.servalproject.servaldna.rhizome.RhizomeEncryptionException;
import org.servalproject.servaldna.rhizome.RhizomeFakeManifestException;
import org.servalproject.servaldna.rhizome.RhizomeIncompleteManifest;
import org.servalproject.servaldna.rhizome.RhizomeInconsistencyException;
import org.servalproject.servaldna.rhizome.RhizomeInsertBundle;
import org.servalproject.servaldna.rhizome.RhizomeInvalidManifestException;
import org.servalproject.servaldna.rhizome.RhizomeManifestBundle;
import org.servalproject.servaldna.rhizome.RhizomePayloadBundle;
import org.servalproject.servaldna.rhizome.RhizomePayloadRawBundle;
import org.servalproject.servaldna.rhizome.RhizomeReadOnlyException;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.Vector;

public class ServalDClient implements ServalDHttpConnectionFactory {
	private final int httpPort;
	private final String restfulUsername;
	private final String restfulPassword;

	public ServalDClient(int httpPort, String restfulUsername, String restfulPassword) throws ServalDInterfaceException {
		if (httpPort < 1 || httpPort > 65535)
			throw new ServalDInterfaceException("invalid HTTP port number: " + httpPort);
		if (restfulUsername == null)
			throw new ServalDInterfaceException("invalid HTTP username");
		if (restfulPassword == null)
			throw new ServalDInterfaceException("invalid HTTP password");
		this.httpPort = httpPort;
		this.restfulUsername = restfulUsername;
		this.restfulPassword = restfulPassword;
	}

	public KeyringIdentityList keyringListIdentities(String pin) throws ServalDInterfaceException, IOException {
		KeyringIdentityList list = new KeyringIdentityList(this);
		list.connect(pin);
		return list;
	}

	public KeyringIdentity keyringSetDidName(Subscriber subscriber, String did, String name, String pin) throws ServalDInterfaceException, IOException
	{
		return this.keyringSetDidName(subscriber.sid, did, name, pin);
	}

	public KeyringIdentity keyringSetDidName(SubscriberId sid, String did, String name, String pin) throws ServalDInterfaceException, IOException
	{
		return KeyringCommon.setDidName(this, sid, did, name, pin);
	}

	public KeyringIdentity keyringAdd(String did, String name, String pin) throws ServalDInterfaceException, IOException
	{
		return KeyringCommon.addIdentity(this, did, name, pin);
	}

	public KeyringIdentity keyringRemove(SubscriberId sid, String pin) throws ServalDInterfaceException, IOException
	{
		return KeyringCommon.removeIdentity(this, sid, pin);
	}

	public RhizomeBundleList rhizomeListBundles() throws ServalDInterfaceException, IOException
	{
		RhizomeBundleList list = new RhizomeBundleList(this);
		list.connect();
		return list;
	}

	public RhizomeBundleList rhizomeListBundlesSince(String token) throws ServalDInterfaceException, IOException
	{
		RhizomeBundleList list = new RhizomeBundleList(this, token);
		list.connect();
		return list;
	}

	public RhizomeManifestBundle rhizomeManifest(BundleId bid) throws ServalDInterfaceException, IOException
	{
		return RhizomeCommon.rhizomeManifest(this, bid);
	}

	public RhizomePayloadRawBundle rhizomePayloadRaw(BundleId bid) throws ServalDInterfaceException, IOException
	{
		return RhizomeCommon.rhizomePayloadRaw(this, bid);
	}

	public RhizomePayloadBundle rhizomePayload(BundleId bid) throws ServalDInterfaceException, IOException, RhizomeDecryptionException
	{
		return RhizomeCommon.rhizomePayload(this, bid);
	}

	public RhizomeInsertBundle rhizomeInsert(SubscriberId author, RhizomeIncompleteManifest manifest, BundleSecret secret)
		throws	ServalDInterfaceException,
				IOException,
				RhizomeInvalidManifestException,
				RhizomeFakeManifestException,
				RhizomeInconsistencyException,
				RhizomeReadOnlyException,
				RhizomeEncryptionException
	{
		return RhizomeCommon.rhizomeInsert(this, author, manifest, secret);
	}

	public RhizomeInsertBundle rhizomeInsert(SubscriberId author, RhizomeIncompleteManifest manifest, BundleSecret secret, InputStream payloadStream, String fileName)
		throws	ServalDInterfaceException,
				IOException,
				RhizomeInvalidManifestException,
				RhizomeFakeManifestException,
				RhizomeInconsistencyException,
				RhizomeReadOnlyException,
				RhizomeEncryptionException
	{
		return RhizomeCommon.rhizomeInsert(this, author, manifest, secret, payloadStream, fileName);
	}

	public MeshMSConversationList meshmsListConversations(SubscriberId sid) throws ServalDInterfaceException, IOException, MeshMSException
	{
		MeshMSConversationList list = new MeshMSConversationList(this, sid);
		list.connect();
		return list;
	}

	public MeshMSMessageList meshmsListMessages(SubscriberId sid1, SubscriberId sid2) throws IOException, ServalDInterfaceException, MeshMSException
	{
		MeshMSMessageList list = new MeshMSMessageList(this, sid1, sid2);
		list.connect();
		return list;
	}

	public MeshMSMessageList meshmsListMessagesSince(SubscriberId sid1, SubscriberId sid2, String token) throws IOException, ServalDInterfaceException, MeshMSException
	{
		MeshMSMessageList list = new MeshMSMessageList(this, sid1, sid2, token);
		list.connect();
		return list;
	}

	public MeshMSStatus meshmsSendMessage(SubscriberId sid1, SubscriberId sid2, String text) throws IOException, ServalDInterfaceException, MeshMSException
	{
		return MeshMSCommon.sendMessage(this, sid1, sid2, text);
	}

	public MeshMSStatus meshmsMarkAllConversationsRead(SubscriberId sid1) throws IOException, ServalDInterfaceException, MeshMSException
	{
		return MeshMSCommon.markAllConversationsRead(this, sid1);
	}

	public MeshMSStatus meshmsMarkAllMessagesRead(SubscriberId sid1, SubscriberId sid2) throws IOException, ServalDInterfaceException, MeshMSException
	{
		return MeshMSCommon.markAllMessagesRead(this, sid1, sid2);
	}

	public MeshMSStatus meshmsAdvanceReadOffset(SubscriberId sid1, SubscriberId sid2, long offset) throws IOException, ServalDInterfaceException, MeshMSException
	{
		return MeshMSCommon.advanceReadOffset(this, sid1, sid2, offset);
	}

	public int meshmbSendMessage(SigningKey id, String text) throws IOException, ServalDInterfaceException {
		return MeshMBCommon.sendMessage(this, id, text);
	}

	public MessagePlyList meshmbListMessages(SigningKey id) throws IOException, ServalDInterfaceException {
		return meshmbListMessagesSince(id, null);
	}

	public MessagePlyList meshmbListMessagesSince(SigningKey id, String token) throws IOException, ServalDInterfaceException {
		MessagePlyList list = new MessagePlyList(this, id, token);
		list.connect();
		return list;
	}

	public int meshmbFollow(Subscriber id, SigningKey peer) throws ServalDInterfaceException, IOException {
		return MeshMBCommon.follow(this, id, peer);
	}

	public int meshmbIgnore(Subscriber id, SigningKey peer) throws ServalDInterfaceException, IOException {
		return MeshMBCommon.ignore(this, id, peer);
	}

	public MeshMBSubscriptionList meshmbSubscriptions(Subscriber identity) throws IOException, ServalDInterfaceException {
		MeshMBSubscriptionList list = new MeshMBSubscriptionList(this, identity);
		list.connect();
		return list;
	}

	public MeshMBActivityList meshmbActivity(Subscriber identity) throws IOException, ServalDInterfaceException {
		return meshmbActivity(identity, null);
	}

	public MeshMBActivityList meshmbActivity(Subscriber identity, String token) throws IOException, ServalDInterfaceException {
		MeshMBActivityList list = new MeshMBActivityList(this, identity, token);
		list.connect();
		return list;
	}

	// interface ServalDHttpConnectionFactory
	public HttpURLConnection newServalDHttpConnection(String path) throws ServalDInterfaceException, IOException
	{
		return newServalDHttpConnection(path, new Vector<QueryParam>());
	}

	// interface ServalDHttpConnectionFactory
	public HttpURLConnection newServalDHttpConnection(String path, Iterable<QueryParam> query_params) throws ServalDInterfaceException, IOException
	{
		StringBuilder str = new StringBuilder();
		char sep = '?';
		for (QueryParam param : query_params) {
			str.append(sep);
			param.uri_encode(str);
			sep = '&';
		}
		URL url = new URL("http://127.0.0.1:" + httpPort + path + str.toString());
		URLConnection uconn = url.openConnection();
		HttpURLConnection conn;
		try {
			conn = (HttpURLConnection) uconn;
		}
		catch (ClassCastException e) {
			throw new ServalDInterfaceException("URL.openConnection() returned a " + uconn.getClass().getName() + ", expecting a HttpURLConnection", e);
		}
		conn.setAllowUserInteraction(false);
		try {
			conn.addRequestProperty("Authorization", "Basic " + Base64.encode((restfulUsername + ":" + restfulPassword).getBytes("UTF-8")));
		}
		catch (UnsupportedEncodingException e) {
			throw new ServalDInterfaceException("invalid RESTful password", e);
		}
		return conn;
	}

}
