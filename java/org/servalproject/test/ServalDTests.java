package org.servalproject.test;

import org.servalproject.servaldna.IJniResults;
import org.servalproject.servaldna.ServalDCommand;
import org.servalproject.servaldna.ServalDFailureException;

import java.util.Arrays;

class ServalDTests
{
	public static int printCommand(final String fieldDelim, final String rowDelim, String... args) throws ServalDFailureException {
		return ServalDCommand.command(new IJniResults() {
			int columns = -1;
			int column = -1;

			@Override
			public void startResultSet(int columns) {
				this.columns = columns;
			}

			@Override
			public void setColumnName(int column, String name) {
				System.out.print(name + fieldDelim);
				if (column >= 0 && column + 1 == columns)
					System.out.println();
			}

			private void eol() {
				if (columns == -1 || ++column == columns) {
					System.out.print(rowDelim);
					column = -1;
				}
			}

			@Override
			public void putString(String value) {
				System.out.print(value);
				eol();
			}

			@Override
			public void putBlob(byte[] value) {
				System.out.print(new String(value));
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
			public void totalRowCount(int rows) {
			}
		}, args);
	}

	public static void main(String... args)
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
				printCommand("", " ", args);
				System.out.println();
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
