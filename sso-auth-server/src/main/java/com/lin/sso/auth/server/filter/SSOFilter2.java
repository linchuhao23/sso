package com.lin.sso.auth.server.filter;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.lin.sso.auth.server.listener.support.HttpSessionHolder;
import com.lin.sso.auth.server.util.HttpClientUtils;
/**
 * 过滤器，过滤掉验证的路径
 * @author Administrator
 *
 */
public class SSOFilter2 implements Filter {
	
	public static final String TOKEN = "token";
	
	public static final String CALLBACK_URL = "callbackURL";
	
	public static final String SYS_NAME_PARAM = "sys_name";
	
	public static final String SYS_SESSION_ID_NAME = "sys_session_id";
	
	public static final String SYS_AWARE_LOGOUT_URI_PARAM = "sys_aware_logout_uri";
	
	/*
	 * 子系统的信息
	 */
	private static final ConcurrentHashMap<String, ConcurrentHashMap<String, String>> SYS_LOGOUT_INFO = new ConcurrentHashMap<String, ConcurrentHashMap<String,String>>();
	
	private String loginUrl = "/login";
	
	private String logoutUrl = "/logout";
	
	private String verifyUrl = "/verify";
	
	private String welcomeUrl = "/welcome";

	public void init(FilterConfig filterConfig) throws ServletException {
		
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest _request = (HttpServletRequest) request;
		HttpServletResponse _response = (HttpServletResponse) response;
		HttpSession _session = _request.getSession();
		
		//获取去除项目后的URI
		String uri = _request.getRequestURI().replaceFirst(_request.getContextPath(), "");
		//如果是退出操作
		if (logoutUrl.equals(uri)) {
			//退出操作
			logout(_request, _response);
			return;
		}
		
		//如果是验证
		if (verifyUrl.equals(uri)) {
			verify(_request, _response);
			return;
		}
		
		String token = (String)_session.getAttribute(TOKEN);
		//已经验证过的
		if (token != null) {
			String callbackUrl = _request.getParameter(CALLBACK_URL);
			//如果子系统有返回路径，将token带回去
			if (callbackUrl != null) {
				if (callbackUrl.indexOf("?") != -1) {
					callbackUrl += "&" + TOKEN + "=" + token;
				} else {
					callbackUrl += "?" + TOKEN + "=" + token;
				}
				//返回子系统登录页
				_response.sendRedirect(callbackUrl);
			} else if(welcomeUrl.equals(uri)) {
				//跳转到当前系统的欢迎页
				goToWelcome(_request, _response);
			} else {
				_response.sendRedirect(_request.getContextPath() + welcomeUrl);
			}
			return;
		}
		
		//如果是登录验证路径
		if (loginUrl.equals(uri)) {
			if (_request.getMethod().toUpperCase().equals("POST")) {
				login(_request, _response);
			} else {
				goToLogin(_request, _response);
			}
			return;
		}
		
		//其他情况跳转到登录页
		_response.sendRedirect(_request.getContextPath() + loginUrl);
		
	}

	private void goToLogin(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		InputStream in = request.getSession().getServletContext().getResourceAsStream("login.html");
		ServletOutputStream out = response.getOutputStream();
		byte[] buf = new byte[8192];//8k
		int len = 0;
		while ((len = in.read(buf)) != -1) {
			out.write(buf, 0, len);
		}
		out.flush();
		out.close();
	}

	/**
	 * 登录验证
	 * @param _request
	 * @param _response
	 * @throws ServletException
	 * @throws IOException
	 */
	private void login(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String contextPath = request.getContextPath();
		String username = request.getParameter("username");
		String password = request.getParameter("password");
		if ("admin".equals(username) && "admin".equals(password)) {
			String token = UUID.randomUUID().toString().replaceAll("-", "");
			HttpSession session = request.getSession();
			session.setMaxInactiveInterval(100);//认证中心session不过期
			token = session.getId() + "," + token;
			session.setAttribute(TOKEN, token);
			String callbackUrl = request.getParameter(CALLBACK_URL);
			if (callbackUrl != null && callbackUrl.length() > 0) {
				if (callbackUrl.indexOf("?") != -1) {
					callbackUrl += "&token=" + token;
				} else {
					callbackUrl += "?token=" + token;
				}
			} else {
				callbackUrl = contextPath + "/welcome";
			}
			response.sendRedirect(callbackUrl);
			return;
		}
		response.sendRedirect(contextPath + "/login?" + CALLBACK_URL + "=" + request.getParameter(CALLBACK_URL));
	}

	/**
	 * 验证操作
	 * @param request
	 * @param response
	 * @throws ServletException
	 * @throws IOException
	 */
	private void verify(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String token = request.getParameter(TOKEN);
		String sysName = request.getParameter(SYS_NAME_PARAM);//子系统名称
		String sessionId = request.getParameter(SYS_SESSION_ID_NAME);//子系统中用户的seasoned
		String sysAwareLogoutUrl = request.getParameter(SYS_AWARE_LOGOUT_URI_PARAM);//用户退出子系统通知
		Boolean verify = false;
		//所有参数必须不为空才会验证
		if (isNotEmpty(token) && isNotEmpty(sysName) && isNotEmpty(sessionId) && isNotEmpty(sysAwareLogoutUrl)) {
			String[] split = token.split(",");
			if (split.length == 2) {
				HttpSession httpSession = HttpSessionHolder.get(split[0]);
				//如果session存在并且token相同，说明用户认证成功
				if (httpSession != null && token.equals(httpSession.getAttribute(TOKEN))) {
					verify = true;
					ConcurrentHashMap<String,String> sysInfo = SYS_LOGOUT_INFO.get(httpSession.getId());
					if (sysInfo == null) {
						sysInfo = initSysInfo(httpSession.getId());
					}
					sysInfo.put(sessionId, sysAwareLogoutUrl);
				}
			}
		}
		response.getOutputStream().write(verify.toString().getBytes());
	}
	
	private ConcurrentHashMap<String, String> initSysInfo(String id) {
		ConcurrentHashMap<String, String> sysInfo = SYS_LOGOUT_INFO.get(id);
		if (sysInfo == null) {
			synchronized (SYS_LOGOUT_INFO) {
				sysInfo = SYS_LOGOUT_INFO.get(id);
				if (sysInfo == null) {
					sysInfo = new ConcurrentHashMap<String, String>();
					SYS_LOGOUT_INFO.put(id, sysInfo);
				}
			}
		}
		return sysInfo;
	}

	private boolean isNotEmpty(String val) {
		return val != null && val.length() > 0;
	}

	/**
	 * 退出操作
	 * @param request
	 * @param response
	 * @throws ServletException
	 * @throws IOException
	 */
	private void logout(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		request.getSession().invalidate();//删除session
		response.sendRedirect(request.getContextPath() + loginUrl);//跳转到登录页
	}

	/**
	 * 欢迎页
	 * @param _request
	 * @param _response
	 */
	private void goToWelcome(HttpServletRequest request, HttpServletResponse response)  throws ServletException, IOException {
		InputStream in = request.getSession().getServletContext().getResourceAsStream("welcome.html");
		ServletOutputStream out = response.getOutputStream();
		byte[] buf = new byte[8192];//8k
		int len = 0;
		while ((len = in.read(buf)) != -1) {
			out.write(buf, 0, len);
		}
		out.flush();
		out.close();
	}

	public void destroy() {
		
	}
	
	/**
	 * 通知子系统
	 * @param httpSession
	 */
	public static void sessionDestroyAware(HttpSession httpSession) {
		final ConcurrentHashMap<String, String> sysInfo = SYS_LOGOUT_INFO.remove(httpSession.getId());
		if (sysInfo != null) {
			new Thread(new Runnable() {
				@Override
				public void run() {
					for (Map.Entry<String, String> e : sysInfo.entrySet()) {
						System.out.println("lgout -> " + e.getValue());
						HttpClientUtils.getText(e.getValue() + "?" + SYS_SESSION_ID_NAME + "=" + e.getKey(), null, "utf-8");
					}
				}
			}).start();
		}
	}

}
