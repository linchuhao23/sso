package com.lin.sso.auth.client.listener.support;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.http.HttpSession;

public class HttpSessionHolder {
	
	private final static Map<String, HttpSession> holder = new ConcurrentHashMap<String, HttpSession>();
	
	public static void add(HttpSession httpSession) {
		Objects.requireNonNull(httpSession);
		holder.put(httpSession.getId(), httpSession);
	}
	
	public static void remove(HttpSession httpSession) {
		Objects.requireNonNull(httpSession);
		holder.remove(httpSession.getId());
	}
	
	public static HttpSession get(String sessionId) {
		return holder.get(sessionId);
	}

}
