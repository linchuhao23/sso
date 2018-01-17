package com.lin.sso.auth.server.listener;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import com.lin.sso.auth.server.filter.SSOFilter2;
import com.lin.sso.auth.server.listener.support.HttpSessionHolder;

public class SessionListener implements HttpSessionListener {

	public void sessionCreated(HttpSessionEvent se) {
		HttpSessionHolder.add(se.getSession());
	}

	public void sessionDestroyed(HttpSessionEvent se) {
		HttpSession session = se.getSession();
		HttpSessionHolder.remove(session);
		SSOFilter2.sessionDestroyAware(session);
	}

}
