package com.lin.sso.auth.client.listener;

import javax.servlet.http.HttpSessionEvent;

import com.lin.sso.auth.client.listener.support.HttpSessionHolder;

public class HttpSessionListener implements javax.servlet.http.HttpSessionListener {

	public void sessionCreated(HttpSessionEvent se) {
		HttpSessionHolder.add(se.getSession());
	}

	public void sessionDestroyed(HttpSessionEvent se) {
		HttpSessionHolder.remove(se.getSession());
	}

}
