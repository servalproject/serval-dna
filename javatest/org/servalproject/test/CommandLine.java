package org.servalproject.test;

import org.servalproject.servaldna.AsyncResult;
import org.servalproject.servaldna.ChannelSelector;
import org.servalproject.servaldna.IJniServer;
import org.servalproject.servaldna.MdpDnaLookup;
import org.servalproject.servaldna.MdpServiceLookup;
import org.servalproject.servaldna.ResultList;
import org.servalproject.servaldna.ServalDCommand;
import org.servalproject.servaldna.ServalDFailureException;
import org.servalproject.servaldna.ServalDInterfaceException;
import org.servalproject.servaldna.ServerControl;
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
		System.err.println(new Date().toString()+" "+msg);
	}

	static void getPeers() throws ServalDFailureException {
		List<ServalDCommand.IdentityResult> peers = new LinkedList<ServalDCommand.IdentityResult>();
		ServalDCommand.idPeers(new ResultList<ServalDCommand.IdentityResult>(peers));

		for(ServalDCommand.IdentityResult i:peers){
			ServalDCommand.IdentityResult details = ServalDCommand.reverseLookup(i.subscriberId);
			System.out.println(details.getResult()==0?details.toString():i.toString());
		}
	}

	static void lookup(String did) throws IOException, InterruptedException, ServalDInterfaceException {
		MdpDnaLookup lookup = new ServerControl().getMdpDnaLookup(new ChannelSelector(),  new AsyncResult<ServalDCommand.LookupResult>() {
			@Override
			public void result(ServalDCommand.LookupResult nextResult) {
				System.out.println(nextResult.toString());
			}
		});
		lookup.sendRequest(SubscriberId.broadcastSid, did);
		Thread.sleep(3000);
		lookup.close();
	}

	static void service(String pattern) throws IOException, InterruptedException, ServalDInterfaceException {
		MdpServiceLookup lookup = new ServerControl().getMdpServiceLookup(new ChannelSelector(), new AsyncResult<MdpServiceLookup.ServiceResult>() {
			@Override
			public void result(MdpServiceLookup.ServiceResult nextResult) {
				System.out.println(nextResult.toString());
			}
		});
		lookup.sendRequest(SubscriberId.broadcastSid, pattern);
		Thread.sleep(3000);
		lookup.close();
	}

	private static Runnable server = new Runnable() {
		@Override
		public void run() {
			ServalDCommand.server(new IJniServer() {
				@Override
				public long aboutToWait(long now, long nextRun, long nextWake) {
					return nextWake;
				}

				@Override
				public void wokeUp() {
				}

				@Override
				public void started(String instancePath, int pid, int mdpPort, int httpPort) {
					System.err.println("Started instance " + instancePath);
					synchronized (server) {
						server.notifyAll();
					}
				}
			}, "", new String[]{""});
		}
	};

	private static class ServerStopped extends RuntimeException{}

	private static void server() throws InterruptedException, ServalDFailureException {
		System.err.println("Starting server thread");
		Thread serverThread = new Thread(server, "server");
		serverThread.start();

		System.err.println("Waiting for server to start");
		synchronized (server) {
			server.wait();
		}

		Thread.sleep(500);
		ServalDCommand.configSync();
		Thread.sleep(500);

		// Note, we don't really support stopping the server cleanly from within the JVM.
		System.exit(0);
	}

	public static void main(String... args){
		if (args.length<1)
			return;

		try {
			String methodName = args[0];
			Object result=null;
			if (methodName.equals("server"))
				server();
			if (methodName.equals("start"))
				result=ServalDCommand.serverStart();
			if (methodName.equals("stop"))
				result=ServalDCommand.serverStop();
			if (methodName.equals("peers"))
				getPeers();
			if (methodName.equals("lookup"))
				lookup(args.length >= 2 ? args[1] : "");
			if (methodName.equals("service"))
				service(args.length >= 2 ? args[1] : "");

			if (result!=null)
				System.err.println(result.toString());

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
