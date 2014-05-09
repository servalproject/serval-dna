package org.servalproject.servaldna;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.DatagramChannel;

/**
 * Created by jeremy on 17/02/14.
 */
public class MdpPacket {
	private ByteBuffer buff;
	public ByteBuffer payload;

	private static final int MDP_MTU = 1200;
	private static final int HEADER_LEN = 32+4+32+4+1+1+1;

	public static final byte MDP_FLAG_NO_CRYPT = (1<<0);
	public static final byte MDP_FLAG_NO_SIGN = (1<<1);
	public static final byte MDP_FLAG_BIND = (1<<2);
	public static final byte MDP_FLAG_CLOSE = (1<<3);
	public static final byte MDP_FLAG_ERROR = (1<<4);

	public static final int MDP_PORT_ECHO = 7;
	public static final int MDP_PORT_DNALOOKUP = 10;
	public static final int MDP_PORT_SERVICE_DISCOVERY = 11;

	public MdpPacket(){
		buff = ByteBuffer.allocate(MDP_MTU);
		buff.order(ByteOrder.nativeOrder());
		buff.position(HEADER_LEN);
		payload = buff.slice();
	}

	public MdpPacket prepareReply(){
		MdpPacket reply = new MdpPacket();
		buff.position(0);
		buff.limit(HEADER_LEN);
		reply.buff.position(0);
		reply.buff.put(buff);
		return reply;
	}

	public SubscriberId getLocalSid() throws AbstractId.InvalidBinaryException {
		buff.position(0);
		return new SubscriberId(buff);
	}

	public void setLocalSid(SubscriberId local_sid){
		buff.position(0);
		local_sid.toByteBuffer(buff);
	}

	public int getLocalPort(){
		buff.position(32);
		return buff.getInt();
	}

	public void setLocalPort(int local_port){
		buff.position(32);
		buff.putInt(local_port);
	}

	public SubscriberId getRemoteSid() throws AbstractId.InvalidBinaryException {
		buff.position(32+4);
		return new SubscriberId(buff);
	}

	public void setRemoteSid(SubscriberId local_sid){
		buff.position(32+4);
		local_sid.toByteBuffer(buff);
	}

	public int getRemotePort(){
		buff.position(32+4+32);
		return buff.getInt();
	}

	public void setRemotePort(int remote_port){
		buff.position(32+4+32);
		buff.putInt(remote_port);
	}

	public byte getFlags(){
		buff.position(32+4+32+4);
		return buff.get();
	}

	public void setFlags(byte flags){
		buff.position(32+4+32+4);
		buff.put(flags);
	}

	public byte getQOS(){
		buff.position(32+4+32+4+1);
		return buff.get();
	}

	public void setQOS(byte qos){
		buff.position(32+4+32+4+1);
		buff.put(qos);
	}

	public byte getTTL(){
		buff.position(32+4+32+4+1+1);
		return buff.get();
	}

	public void setTTL(byte ttl){
		buff.position(32+4+32+4+1+1);
		buff.put(ttl);
	}

	public void send(DatagramChannel channel) throws IOException {
		buff.clear();
		buff.limit(HEADER_LEN+payload.limit());
		channel.write(buff);
	}

	public void receive(DatagramChannel channel) throws IOException {
		buff.clear();
		channel.read(buff);
		buff.flip();
		if (buff.remaining() < HEADER_LEN)
			throw new MdpSocket.MdpError("Received packet is too short");
		payload.position(0);
		payload.limit(buff.limit() - HEADER_LEN);
	}

}
