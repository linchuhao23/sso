package com.lin.sso.auth.client.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HttpClientUtils {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(HttpClientUtils.class);

	private HttpClientUtils() {
	}

	/**
	 * 根据路径获取页面的html内容
	 * @param url
	 * @param variables
	 * @param encoding
	 * @return
	 */
	public static String getText(String url, Map<String, String> variables, String encoding) {
		
		String body = null;
		
		// 创建httpclient对象
		CloseableHttpClient client = HttpClients.createDefault();
		
		// 创建post方式请求对象
		HttpGet httpGet = new HttpGet(url);
		
		// 装填参数
		List<NameValuePair> nvps = new ArrayList<NameValuePair>();
		if (variables != null) {
			for (Map.Entry<String, String> entry : variables.entrySet()) {
				nvps.add(new BasicNameValuePair(entry.getKey(), entry.getValue()));
			}
		}

		// 设置header信息
		// 指定报文头【Content-type】、【User-Agent】
		httpGet.setHeader("Content-type", "application/x-www-form-urlencoded");
		httpGet.setHeader("User-Agent",
				"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36");

		// 执行请求操作，并拿到结果（同步阻塞）
		CloseableHttpResponse response;
		// 获取结果实体
		HttpEntity entity = null;
		
		try {
			response = client.execute(httpGet);
			entity = response.getEntity();
			if (entity != null) {
				// 按指定编码转换结果实体为String类型
				body = EntityUtils.toString(entity, encoding);
			}
		} catch (IOException e) {
			LOGGER.error("{}", e);
		} finally {
			EntityUtils.consumeQuietly(entity);
		}
		
		return body;
	}
	
	/**
	 * 获取url文件的二进制流，下载文件和图片的时候可以用
	 * @param url
	 * @param variables
	 * @param encoding
	 * @return
	 */
	public static byte[] getBytes(String url, Map<String, String> variables) {
		
		// 创建httpclient对象
		CloseableHttpClient client = HttpClients.createDefault();
		
		// 创建post方式请求对象
		HttpGet httpGet = new HttpGet(url);
		
		// 装填参数
		List<NameValuePair> nvps = new ArrayList<NameValuePair>();
		if (variables != null) {
			for (Map.Entry<String, String> entry : variables.entrySet()) {
				nvps.add(new BasicNameValuePair(entry.getKey(), entry.getValue()));
			}
		}

		// 设置header信息
		// 指定报文头【Content-type】、【User-Agent】
		httpGet.setHeader("Content-type", "application/x-www-form-urlencoded");
		httpGet.setHeader("User-Agent",
				"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36");

		// 执行请求操作，并拿到结果（同步阻塞）
		CloseableHttpResponse response;
		// 获取结果实体
		HttpEntity entity = null;
		
		try {
			response = client.execute(httpGet);
			entity = response.getEntity();
			InputStream content = entity.getContent();
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			byte[] buf = new byte[1024];
			int len = 0;
			while ((len = content.read(buf)) > 0) {
				out.write(buf, 0, len);
			}
			return out.toByteArray();
		} catch (IOException e) {
			LOGGER.error("{}", e);
		} finally {
			EntityUtils.consumeQuietly(entity);
		}
		
		return null;
	}

}
