package org.servalproject.test;

import org.servalproject.servaldna.ResultList;
import org.servalproject.servaldna.ServalDCommand;
import org.servalproject.servaldna.ServalDFailureException;

import java.util.LinkedList;
import java.util.List;

/**
 * Created by jeremy on 20/02/14.
 */
public class CommandLine {

	static void getPeers() throws ServalDFailureException {
		List<ServalDCommand.IdentityResult> peers = new LinkedList<ServalDCommand.IdentityResult>();
		ServalDCommand.idPeers(new ResultList<ServalDCommand.IdentityResult>(peers));

		for(ServalDCommand.IdentityResult i:peers){
			ServalDCommand.IdentityResult details = ServalDCommand.reverseLookup(i.subscriberId);
			System.out.println(details.getResult()==0?details.toString():i.toString());
		}
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

			if (result!=null)
				System.out.println(result.toString());

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
