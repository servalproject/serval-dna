package org.servalproject.servald;

import java.lang.reflect.*;
import java.util.Arrays;
import org.servalproject.servald.ServalD;
import org.servalproject.servald.ServalDResult;

class ServalDTests
{
	public static void main(String[] args)
	{
		try {
			Class cls = new Object() { }.getClass().getEnclosingClass();
			Method m = cls.getMethod(args[0], String[].class);
			m.invoke(null, (Object) Arrays.copyOfRange(args, 1, args.length));
		}
		catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.exit(0);
	}

	public static void repeat(String[] args)
	{
		int repeat = Integer.decode(args[0]);
		ServalD sdi = new ServalD();
		for (int i = 0; i != repeat; ++i) {
			ServalDResult res = sdi.command(Arrays.copyOfRange(args, 1, args.length));
			System.out.print(res.status);
			for (String s: res.outv) {
				System.out.print(":");
				System.out.print(s);
			}
			System.out.println("");
		}
	}
}
