package org.servalproject.servaldna;

import java.io.IOException;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;

/**
 * Created by jeremy on 21/02/14.
 */
public class MdpDnaLookup extends ChannelSelector.Handler{
	private final ChannelSelector selector;
	private final MdpSocket socket;
	private final AsyncResult<ServalDCommand.LookupResult> results;

	public MdpDnaLookup(ChannelSelector selector, AsyncResult<ServalDCommand.LookupResult> results) throws IOException {
		socket = new MdpSocket();
		socket.bind();
		this.selector = selector;
		this.results = results;
		selector.register(this);
	}

	public void sendRequest(SubscriberId destination, String did) throws IOException {
		MdpPacket request = new MdpPacket();
		if (destination.isBroadcast())
			request.setFlags(MdpPacket.MDP_FLAG_NO_CRYPT);
		request.setRemoteSid(destination);
		request.setRemotePort(MdpPacket.MDP_PORT_DNALOOKUP);
		request.payload.put(did.getBytes());
		request.payload.put((byte)0);
		request.payload.flip();
		socket.send(request);
	}

	@Override
	public void read() {
		try {
			MdpPacket response = new MdpPacket();
			socket.receive(response);
			byte bytes[] = new byte[response.payload.remaining()];
			response.payload.get(bytes);
			String resultString = new String(bytes);
			String fields[] = resultString.split("\\|");
			if (fields.length < 2)
				throw new IOException("Expected at least 2 result fields, got \""+resultString+"\"");
			ServalDCommand.LookupResult result = new ServalDCommand.LookupResult();
			result.subscriberId = new SubscriberId(fields[0]);
			result.uri = fields[1];
			result.did = (fields.length>2)?fields[2]:"";
			result.name = (fields.length>3)?fields[3]:"";
			results.result(result);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (AbstractId.InvalidHexException e) {
			e.printStackTrace();
		}

	}

	public void close(){
		try {
			selector.unregister(this);
		} catch (IOException e) {
			e.printStackTrace();
		}
		socket.close();
	}

	@Override
	public SelectableChannel getChannel() throws IOException {
		return socket.getChannel();
	}

	@Override
	public int getInterest() {
		return SelectionKey.OP_READ;
	}
}
