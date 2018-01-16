package com.lin.sso.auth.server.listener;

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

public class SessionListener implements HttpSessionListener {

	public void sessionCreated(HttpSessionEvent se) {
		SessionIdHolder.add(se.getSession());
	}

	public void sessionDestroyed(HttpSessionEvent se) {
		SessionIdHolder.remove(se.getSession());
	}

}
