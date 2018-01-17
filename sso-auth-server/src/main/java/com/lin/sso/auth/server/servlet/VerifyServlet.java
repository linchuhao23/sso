package com.lin.sso.auth.server.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.lin.sso.auth.server.filter.SSOFilter;
import com.lin.sso.auth.server.listener.support.HttpSessionHolder;

public class VerifyServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String token = req.getParameter(SSOFilter.TOKEN);
		Boolean verify = false;
		if (token != null && token.length() > 0) {
			String[] split = token.split(",");
			if (split.length == 2) {
				String sessionId = split[0];
				HttpSession httpSession = HttpSessionHolder.get(sessionId);
				if (httpSession != null) {
					Object _token = httpSession.getAttribute(SSOFilter.TOKEN);
					if (_token != null && token.equals(_token)) {
						verify = true;
					}
				}
			}
		}
		resp.getOutputStream().write(verify.toString().getBytes());
	}
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		doPost(req, resp);
	}

}
