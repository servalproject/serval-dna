/**
 * Copyright (C) 2016 Flinders University
 * Copyright (C) 2014-2015 Serval Project Inc.
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

import org.servalproject.servaldna.ServalDCommand;
import org.servalproject.servaldna.ServalDFailureException;
import org.servalproject.servaldna.AbstractId;
import org.servalproject.servaldna.IJniResults;

import java.util.Arrays;

public class CommandLine {

	public static void command(String... args) throws ServalDFailureException {
		ServalDCommand.command(new IJniResults() {
			int column_count = -1;
			int column = 0;

			private void eol() {
				if (column_count == -1 || ++column >= column_count) {
					System.out.println("");
					column = 0;
				}
				else
					System.out.print(":");
			}

			@Override
			public void putString(String value) {
				System.out.print(value);
				eol();
			}

			@Override
			public void putLong(long value) {
				System.out.print(value);
				eol();
			}

			@Override
			public void putDouble(double value) {
				System.out.print(value);
				eol();
			}

			@Override
			public void putBlob(byte[] blob) {
				System.out.print(new String(blob));
				eol();
			}

			@Override
			public void putHexValue(byte[] blob) {
				System.out.print(AbstractId.toHex(blob));
				eol();
			}

			@Override
			public void startTable(int column_count) {
				this.column_count = column_count;
				System.out.println(column_count);
			}

			@Override
			public void setColumnName(int column, String name) {
				System.out.print(name);
				if (column + 1 >= column_count)
					System.out.println("");
				else
					System.out.print(":");
			}

			@Override
			public void endTable(int rows) {
				this.column_count = -1;
			}
		}, args);
	}

	public static void main(String... args) {
		try {
			for (int i = 0; i != args.length; ++i)
				if ("(null)".equals(args[i]))
					args[i] = null;

			int repeatCount = 1;
			if (args[0].equals("--repeat")) {
				repeatCount = Integer.decode(args[1]);
				args = Arrays.copyOfRange(args, 2, args.length);
			}

			while (repeatCount-- > 0) {
				command(args);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
