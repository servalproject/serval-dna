/**
 * Copyright (C) 2016 Flinders University
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

public class ServalDTests
{
	static void log(String msg) {
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

	private static class ServerRunnable implements Runnable {
		public boolean running = false;

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
					System.out.println("Started server pid=" + pid + " instance=" + instancePath);
					synchronized (server) {
						running = true;
						server.notifyAll();
					}
				}
			}, "", new String[]{""});

			synchronized (server) {
				running = false;
				server.notifyAll();
			}
		}
	}

	private static ServerRunnable server = new ServerRunnable();

	private static class ServerStopped extends RuntimeException{}

	private static void server() throws InterruptedException, ServalDFailureException {
		System.out.println("Starting server thread");
		Thread serverThread = new Thread(server, "server");
		serverThread.start();

		synchronized (server) {
			while (!server.running) {
				System.out.println("Waiting for server to start");
				server.wait();
			}
		}

		synchronized (server) {
			while (server.running) {
				System.out.println("Waiting for server to stop");
				server.wait();
			}
		}
	}

	public static void main(String... args)
	{
		try {
			String methodName = args[0];
			Object result = null;
			if (methodName.equals("server"))
				server();
			else if (methodName.equals("start"))
				result=ServalDCommand.serverStart();
			else if (methodName.equals("stop"))
				result=ServalDCommand.serverStop();
			else if (methodName.equals("peers"))
				getPeers();
			else if (methodName.equals("lookup"))
				lookup(args.length >= 2 ? args[1] : "");
			else if (methodName.equals("service"))
				service(args.length >= 2 ? args[1] : "");
			else
				throw new Exception("unknown command: " + methodName);

			if (result != null)
				System.err.println(result.toString());
		}
		catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.exit(0);
	}
}
