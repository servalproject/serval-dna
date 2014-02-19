package org.servalproject.servaldna;

/**
 * Created by jeremy on 18/02/14.
 */
public abstract class JniResultList<T extends JniResult> implements IJniResults {
	private String names[];
	private int column =-1;
	private int columns = -1;
	private T currentRow;
	private AsyncResult<T> results;

	public JniResultList(AsyncResult<T> results){
		this.results = results;
	}
	public abstract T create();

	@Override
	public void startResultSet(int columns) {
		names = new String[columns];
		this.columns = columns;
	}

	@Override
	public void setColumnName(int column, String name) {
		names[column]=name;
	}

	private void prepareCol(){
		column++;
		if (column==0)
			currentRow = create();
		currentRow.columnName = names[column];
	}
	private void endCol(){
		if (column+1>=columns){
			if (currentRow!=null)
				results.result(currentRow);
			currentRow=null;
			column=-1;
		}
	}

	@Override
	public void putString(String value) {
		prepareCol();
		currentRow.putString(value);
		endCol();
	}

	@Override
	public void putBlob(byte[] value) {
		prepareCol();
		currentRow.putBlob(value);
		endCol();
	}

	@Override
	public void putLong(long value) {
		prepareCol();
		currentRow.putLong(value);
		endCol();
	}

	@Override
	public void putDouble(double value) {
		prepareCol();
		currentRow.putDouble(value);
		endCol();
	}

	@Override
	public void totalRowCount(int rows) {
	}
}
