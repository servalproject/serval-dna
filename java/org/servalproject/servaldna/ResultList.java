package org.servalproject.servaldna;

import java.util.List;

/**
 * Created by jeremy on 20/02/14.
 */
public class ResultList<T> implements AsyncResult<T> {
	private final List<T> results;
	public ResultList(List<T> results){
		this.results = results;
	}

	@Override
	public void result(T nextResult) {
		results.add(nextResult);
	}
}
