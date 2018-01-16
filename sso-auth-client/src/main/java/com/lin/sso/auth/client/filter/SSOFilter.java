package com.lin.sso.auth.client.filter;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.lin.sso.auth.client.util.HttpClientUtils;

public class SSOFilter implements Filter {
	
	private static final String SSO_SERVER_URL_PARAMETER_NAME = "SSO_SERVER_URL";
	
	private static final String SSO_SERVER_VERIFY_URL_PARAMETER_NAME = "SSO_SERVER_VERIFY_URL";
	
	//登录认证
	private static final String TOKEN = "token";
	
	//private final Logger logger = LoggerFactory.getLogger(SSOFilter.class);
	
	private String SSO_SERVER_URL;
	
	private String SSO_SERVER_VERIFY_URL;
	
	public void destroy() {
		
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest _request = (HttpServletRequest) request;
		String token = (String)_request.getSession().getAttribute(TOKEN);
		
		//如果已经验证成功过的，直接进入下一步
		if (token != null && token.length() > 0) {
			//这里如果用redis，可以更新redis的过期时间
			chain.doFilter(request, response);
			return;
		}
		
		token = _request.getParameter(TOKEN);
		boolean isVerify = false;
		//验证过后重定向过来的
		if (token != null && token.length() > 0) {
			//这里需要去认证中心认证
			isVerify = verify(SSO_SERVER_VERIFY_URL, token);
		}
		
		//如果没有登录，或者认证失败，重新跳到登录页
		if (!isVerify) {
			 //跳转至sso认证中心
			 String callbackURL = _request.getRequestURL().toString();
			 StringBuilder url = new StringBuilder();
			 url.append(SSO_SERVER_URL).append("?callbackURL=").append(callbackURL);
			 ((HttpServletResponse)response).sendRedirect(url.toString());
			 return;
		}
		
		//添加认证成功标识
		_request.getSession().setAttribute(TOKEN, token);
		chain.doFilter(request, response);
		
	}

	public void init(FilterConfig filterConfig) throws ServletException {
		SSO_SERVER_URL = Objects.requireNonNull(filterConfig.getInitParameter(SSO_SERVER_URL_PARAMETER_NAME), "SSO_SERVER_URL can not be null");
		SSO_SERVER_VERIFY_URL = Objects.requireNonNull(filterConfig.getInitParameter(SSO_SERVER_VERIFY_URL_PARAMETER_NAME), "SSO_SERVER_VERIFY_URL can not be null");
	}
	
	/**
	 * 认证
	 * @param verifyUrl
	 * @param token
	 * @return
	 */
	private boolean verify(String verifyUrl, String token) {
		String text = HttpClientUtils.getText(verifyUrl + "?" + TOKEN + "=" + token, null , "utf-8");
		System.out.println(text);
		if ("true".equalsIgnoreCase(text)) {
			return true;
		}
		return false;
	}
	
	/** 
     * 获取用户真实IP地址，不使用request.getRemoteAddr();的原因是有可能用户使用了代理软件方式避免真实IP地址, 
     * 参考文章： http://developer.51cto.com/art/201111/305181.htm 
     *  
     * 可是，如果通过了多级反向代理的话，X-Forwarded-For的值并不止一个，而是一串IP值，究竟哪个才是真正的用户端的真实IP呢？ 
     * 答案是取X-Forwarded-For中第一个非unknown的有效IP字符串。 
     *  
     * 如：X-Forwarded-For：192.168.1.110, 192.168.1.120, 192.168.1.130, 
     * 192.168.1.100 
     *  
     * 用户真实IP为： 192.168.1.110 
     *  
     * @param request 
     * @return 
     */  
    public static String getRealIP(HttpServletRequest request) {  
        String ip = request.getHeader("x-forwarded-for");
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {  
            ip = request.getHeader("Proxy-Client-IP");
        }  
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {  
            ip = request.getHeader("WL-Proxy-Client-IP");  
        }  
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {  
            ip = request.getHeader("HTTP_CLIENT_IP");  
        }  
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {  
            ip = request.getHeader("HTTP_X_FORWARDED_FOR");  
        }  
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {  
            ip = request.getRemoteAddr();  
        }  
        return ip;
    }  

}
