package com.lin.sso.auth.server.servlet;

import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.lin.sso.auth.server.filter.SSOFilter;

public class LoginServlet extends HttpServlet {
	
	private static final long serialVersionUID = 1L;
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String contextPath = req.getContextPath();
		String username = req.getParameter("username");
		String password = req.getParameter("password");
		if ("admin".equals(username) && "admin".equals(password)) {
			String token = UUID.randomUUID().toString().replaceAll("-", "");
			HttpSession session = req.getSession();
			token = session.getId() + "," + token;
			session.setAttribute(SSOFilter.TOKEN, token);
			String callbackUrl = req.getParameter(SSOFilter.CALLBACK_URL);
			if (callbackUrl != null && callbackUrl.length() > 0) {
				if (callbackUrl.indexOf("?") != -1) {
					callbackUrl += "&token=" + token;
				} else {
					callbackUrl += "?token=" + token;
				}
			} else {
				callbackUrl += contextPath + "/welcome.html";
			}
			resp.sendRedirect(callbackUrl);
			return;
		}
		resp.sendRedirect(contextPath + "/login");
	}
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		InputStream in = req.getSession().getServletContext().getResourceAsStream("login.html");
		ServletOutputStream out = resp.getOutputStream();
		byte[] buf = new byte[8192];//8k
		int len = 0;
		while ((len = in.read(buf)) != -1) {
			out.write(buf, 0, len);
		}
		out.flush();
		out.close();
	}
	
	public String getRootPath() {
        String path = LoginServlet.class.getClassLoader().getResource("").getPath();
        if (path.charAt(0) == '/') {
            path = path.substring(1);
        }
        return path.substring(0, path.indexOf("WEB-INF"));
    }
}
