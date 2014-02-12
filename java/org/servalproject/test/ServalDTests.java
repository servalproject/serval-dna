package org.servalproject.test;

import org.servalproject.servaldna.ServalDCommand;
import org.servalproject.servaldna.ServalDResult;

import java.util.Arrays;

class ServalDTests
{
	public static void main(String[] args)
	{
		try {
			for (int i = 0; i != args.length; ++i)
				if ("(null)".equals(args[i]))
					args[i] = null;

			int repeatCount=1;

			if (args[0].equals("repeat")){
				repeatCount = Integer.decode(args[1]);
				args = Arrays.copyOfRange(args, 2, args.length);
			}

			while(repeatCount>0){
				ServalDResult result = ServalDCommand.command(args);
				System.out.print(result.status);
				for (byte[] a: result.outv) {
					System.out.print(":");
					System.out.print(new String(a));
				}
				System.out.println("");

				repeatCount--;
			}
		}
		catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.exit(0);
	}
}
