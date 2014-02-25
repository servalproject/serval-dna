package org.servalproject.test;

import org.servalproject.servaldna.AsyncResult;
import org.servalproject.servaldna.ChannelSelector;
import org.servalproject.servaldna.MdpDnaLookup;
import org.servalproject.servaldna.MdpSocket;
import org.servalproject.servaldna.ResultList;
import org.servalproject.servaldna.ServalDCommand;
import org.servalproject.servaldna.ServalDFailureException;
import org.servalproject.servaldna.SubscriberId;

import java.io.IOException;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * Created by jeremy on 20/02/14.
 */
public class CommandLine {

	static void log(String msg){
		System.out.println(new Date().toString()+" "+msg);
	}

	static void getPeers() throws ServalDFailureException {
		List<ServalDCommand.IdentityResult> peers = new LinkedList<ServalDCommand.IdentityResult>();
		ServalDCommand.idPeers(new ResultList<ServalDCommand.IdentityResult>(peers));

		for(ServalDCommand.IdentityResult i:peers){
			ServalDCommand.IdentityResult details = ServalDCommand.reverseLookup(i.subscriberId);
			System.out.println(details.getResult()==0?details.toString():i.toString());
		}
	}

	static void lookup(String did) throws IOException, InterruptedException, ServalDFailureException {
		ServalDCommand.Status s = ServalDCommand.serverStatus();
		System.out.println(s);
		if (s.getResult()!=0)
			throw new ServalDFailureException("Serval daemon isn't running");
		System.out.println(s);
		MdpSocket.loopbackMdpPort = s.mdpInetPort;
		ChannelSelector selector = new ChannelSelector();
		MdpDnaLookup lookup = new MdpDnaLookup(selector, new AsyncResult<ServalDCommand.LookupResult>() {
			@Override
			public void result(ServalDCommand.LookupResult nextResult) {
				System.out.println(nextResult.toString());
			}
		});
		lookup.sendRequest(SubscriberId.broadcastSid, did);
		Thread.sleep(3000);
		lookup.close();
	}

	public static void main(String... args){
		if (args.length<1)
			return;

		try {
			String methodName = args[0];
			Object result=null;
			if (methodName.equals("start"))
				result=ServalDCommand.serverStart();
			if (methodName.equals("stop"))
				result=ServalDCommand.serverStop();
			if (methodName.equals("peers"))
				getPeers();
			if (methodName.equals("lookup"))
				lookup(args.length>=2 ? args[1] : "");

			if (result!=null)
				System.out.println(result.toString());

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
