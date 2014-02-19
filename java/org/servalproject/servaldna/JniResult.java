package org.servalproject.servaldna;

/**
 * Created by jeremy on 18/02/14.
 */
public class JniResult implements IJniResults{
	protected String columnName=null;
	protected String command[];
	protected int result;

	void setCommand(String command[]){
		this.command = command;
	}
	void setResult(int result) throws ServalDFailureException {
		this.result = result;
		if (result == ServalDCommand.STATUS_ERROR)
			throw new ServalDFailureException("Command \"" + ServalDCommand.toString(command)+"\" returned an error");
	}

	public int getResult(){
		return result;
	}

	@Override
	public void startResultSet(int columns) {
	}

	@Override
	public void setColumnName(int column, String name) {
		columnName=name;
	}

	@Override
	public void putString(String value) {

	}

	@Override
	public void putBlob(byte[] value) {

	}

	@Override
	public void putLong(long value) {

	}

	@Override
	public void putDouble(double value) {

	}

	@Override
	public void totalRowCount(int rows) {
	}
}
