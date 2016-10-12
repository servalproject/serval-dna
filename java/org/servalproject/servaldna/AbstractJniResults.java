package org.servalproject.servaldna;

public abstract class AbstractJniResults implements IJniResults {

	@Override
	public void putString(String value) {
		putBlob((value != null) ? value.getBytes() : null);
	}

	@Override
	public void putLong(long value) {
		putBlob(Long.toString(value).getBytes());
	}

	@Override
	public void putDouble(double value) {
		putBlob(Double.toString(value).getBytes());
	}

	@Override
	public void putHexValue(byte[] value) {
		putBlob(value);
	}

	@Override
	public abstract void putBlob(byte[] blob);

	@Override
	public void startTable(int column_count) {
		putBlob(Integer.toString(column_count).getBytes());
	}

	@Override
	public void setColumnName(int i, String name) {
		putBlob(name.getBytes());
	}

	@Override
	public void endTable(int row_count) {
	}
}
