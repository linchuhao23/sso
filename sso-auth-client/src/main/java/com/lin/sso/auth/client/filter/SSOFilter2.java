package com.lin.sso.auth.client.filter;

import java.io.IOException;
import java.util.Objects;
import java.util.UUID;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.lin.sso.auth.client.listener.support.HttpSessionHolder;
import com.lin.sso.auth.client.util.HttpClientUtils;

public class SSOFilter2 implements Filter {
	
	public static final String TOKEN = "token";
	
	public static final String SSO_SERVER_LOGIN_URL_PARAM = "sso_server_login_url";
	
	public static final String SSO_SERVER_VERIFY_URL_PARAM = "sso_server_verify_url";
	
	public static final String SSO_SERVER_LOGOUT_URL_PARAM = "sso_server_logout_url";
	
	public static final String SYS_NAME_PARAM = "sys_name";
	
	public static final String SYS_LOGOUT_URI_PARAM = "sys_logout_uri";
	
	public static final String SYS_AWARE_LOGOUT_URI_PARAM = "sys_aware_logout_uri";
	
	public static final String SYS_SESSION_ID_NAME = "sys_session_id";
	
	public static final String CALL_BACK_URL = "callbackURL";
	
	//认证中心的登录路径
	private String sso_server_login_url;
	
	//认证中心的验证路径
	private String sso_server_verify_url;
	
	//认证中心退出的路径
	private String sso_server_logout_url;
	
	//当前系统的名称，唯一
	private String sys_name = UUID.randomUUID().toString().replaceAll("-", "");
	
	//当前系统退出的uri路径
	private String sys_logout_uri = "/logout";
	
	//认证系统通知的用户退出
	private String sys_aware_logout_uri = "/awareLogout";

	public void init(FilterConfig filterConfig) throws ServletException {
		initParams(filterConfig);
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest _request = (HttpServletRequest) request;
		HttpServletResponse _response = (HttpServletResponse) response;
		HttpSession _session = _request.getSession();
		
		String contextPath = _request.getContextPath();
		String uri = _request.getRequestURI().toString();
		if (contextPath != null && contextPath.length() > 0) {
			uri = uri.replaceFirst(contextPath, "");//去除项目名称
		}
		
		//用户退出操作
		if (sys_logout_uri.equals(uri)) {
			//注销session
			_session.invalidate();
			//跳转到认证中心的退出路径
			_response.sendRedirect(sso_server_logout_url);
			return;
		}
		
		//认证中心发送过来的用户退出通知
		if (sys_aware_logout_uri.equals(uri)) {
			String sessionId = _request.getParameter(SYS_SESSION_ID_NAME);
			HttpSession httpSession = HttpSessionHolder.get(sessionId);
			if (httpSession != null) {
				httpSession.invalidate();
			}
			return;
		}
		
		String token = (String)_session.getAttribute(TOKEN);
		//已经认证过了
		if (token != null) {
			chain.doFilter(request, response);
			return;
		}
		
		token = _request.getParameter(TOKEN);
		boolean isVerify = false;
		//用户登录后跳转回来的
		if (token != null) {
			isVerify = verfiry(token, _session.getId(), _request);
		}
		
		//如果认证通过
		if (isVerify) {
			_session.setAttribute(TOKEN, token);
			chain.doFilter(request, response);
			return;
		}
		
		//登录验证
		_response.sendRedirect(sso_server_login_url + "?" + CALL_BACK_URL + "=" +  _request.getRequestURL().toString());
		
	}

	public void destroy() {
		
	}
	
	private void initParams(FilterConfig filterConfig) {
		sso_server_login_url = Objects.requireNonNull(filterConfig.getInitParameter(SSO_SERVER_LOGIN_URL_PARAM));
		sso_server_verify_url = Objects.requireNonNull(filterConfig.getInitParameter(SSO_SERVER_VERIFY_URL_PARAM));
		sso_server_logout_url = Objects.requireNonNull(filterConfig.getInitParameter(SSO_SERVER_LOGOUT_URL_PARAM));
		
		sys_name = Objects.toString(filterConfig.getInitParameter(SYS_NAME_PARAM), sys_name);
		sys_logout_uri = Objects.toString(filterConfig.getInitParameter(SYS_LOGOUT_URI_PARAM), sys_logout_uri);
		sys_aware_logout_uri = Objects.toString(filterConfig.getInitParameter(SYS_AWARE_LOGOUT_URI_PARAM), sys_aware_logout_uri);
	}
	
	private boolean verfiry(String token, String sessionId, HttpServletRequest request) {
		String awareUrl = request.getScheme() + "://" + request.getServerName() + ":" //
						+ request.getServerPort() + request.getContextPath() + sys_aware_logout_uri;
		String url = new StringBuilder()//
						.append(sso_server_verify_url).append("?")//
						.append(TOKEN).append("=").append(token)//
						.append("&").append(SYS_NAME_PARAM).append("=").append(sys_name)//
						.append("&").append(SYS_SESSION_ID_NAME).append("=").append(sessionId)//
						.append("&").append(SYS_AWARE_LOGOUT_URI_PARAM).append("=").append(awareUrl)//
						.toString();
		String text = HttpClientUtils.getText(url, null , "utf-8");
		if ("true".equalsIgnoreCase(text)) {
			return true;
		}
		return false;
	}

}
