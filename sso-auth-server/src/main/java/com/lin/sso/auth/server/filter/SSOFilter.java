package com.lin.sso.auth.server.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
/**
 * 过滤器，过滤掉验证的路径
 * @author Administrator
 *
 */
public class SSOFilter implements Filter {
	
	public static final String TOKEN = "token";
	
	public static final String CALLBACK_URL = "callbackURL";
	
	//默认的验证路径
	private String verifyUrl = "/verify";
	
	//登录的路径
	private String loginUrl = "/login";
	
	//退出的路径
	private String logoutUrl = "/logout";
	
	//登录成功后的路径，一般情况用不到
	private String successUrl = "/welcome.html";

	public void init(FilterConfig filterConfig) throws ServletException {
		String initVerifyUrl = filterConfig.getInitParameter("verifyUrl");
		if (initVerifyUrl != null && initVerifyUrl.length() > 0) {
			if (initVerifyUrl.charAt(0) != '/') {
				initVerifyUrl = "/" + initVerifyUrl;
			}
			verifyUrl = initVerifyUrl;
		}
		
		String initLoginUrl = filterConfig.getInitParameter("loginUrl");
		if (initLoginUrl != null && initLoginUrl.length() > 0) {
			if (initLoginUrl.charAt(0) != '/') {
				initLoginUrl = "/" + initLoginUrl;
			}
			loginUrl = initLoginUrl;
		}
		
		String initLogoutUrl = filterConfig.getInitParameter("logoutUrl");
		if (initLogoutUrl != null && initLogoutUrl.length() > 0) {
			if (initLogoutUrl.charAt(0) != '/') {
				initLogoutUrl = "/" + initLogoutUrl;
			}
			logoutUrl = initLogoutUrl;
		}
		
		String initSuccessUrl = filterConfig.getInitParameter("successUrl");
		if (initSuccessUrl != null && initSuccessUrl.length() > 0) {
			if (initSuccessUrl.charAt(0) != '/') {
				initSuccessUrl = "/" + initSuccessUrl;
			}
			successUrl = initSuccessUrl;
		}
		
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest _request = (HttpServletRequest) request;
		HttpServletResponse _response = ((HttpServletResponse)response);
		
		String contextPath = _request.getContextPath();
		String uri = _request.getRequestURI().toString();
		
		//去掉 /sso-auth-server 
		if (contextPath != null && contextPath.length() > 1) {
			uri = uri.replaceFirst(contextPath, "");
		}
		
		//如果是服务客户端发过来的验证，直接通过
		if (uri.equals(verifyUrl)) {
			chain.doFilter(request, response);
			return;
		}
		
		String token = (String)_request.getSession().getAttribute(TOKEN);
		//如果已经认证过了，从一个子系统跳到另一个子系统，需要重新验证
		if (token != null && token.length() > 0) {
			String callbackURL = _request.getParameter(CALLBACK_URL);
			//跳转到子系统
			if (callbackURL != null) {
				if (callbackURL.indexOf("?") != -1) {
					callbackURL += "&token=" + token;
				} else {
					callbackURL += "?token=" + token;
				}
				_response.sendRedirect(callbackURL);
				return;
			}
			
		}
		
		//登录之后跳转到当前系统的欢迎页时，直接跳过
		if (token != null && token.length() > 0 && uri.equals(successUrl)) {
			chain.doFilter(_request, _response);
			return;
		}
		
		//已经登录后又重新到登录页面，直接重定向到欢迎页
		if (token != null && token.length() > 0 && uri.endsWith(loginUrl)) {
			_response.sendRedirect(contextPath + successUrl);
			return;
		}
		
		//没有验证的情况下，登录页，登录验证，退出，直接跳过
		if (token == null && (uri.endsWith(loginUrl) || uri.endsWith(logoutUrl))) {
			chain.doFilter(_request, _response);
			return;
		}
		
		//已经认证，直接跳过，链接不存在时会出现404
		if (token != null && token.length() > 0) {
			chain.doFilter(_request, _response);
			return;
		}
		
		//默认跳转到登录页
		_response.sendRedirect(contextPath + loginUrl);
		
	}

	public void destroy() {
		
	}

}
