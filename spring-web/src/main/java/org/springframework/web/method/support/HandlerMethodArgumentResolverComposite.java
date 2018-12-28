/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.web.method.support;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.MethodParameter;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;

/**
 * Resolves method parameters by delegating to a list of registered
 * {@link HandlerMethodArgumentResolver HandlerMethodArgumentResolvers}.
 * Previously resolved method parameters are cached for faster lookups.
 *
 * @author Rossen Stoyanchev
 * @author Juergen Hoeller
 * @since 3.1
 */
public class HandlerMethodArgumentResolverComposite implements HandlerMethodArgumentResolver {

	protected final Log logger = LogFactory.getLog(getClass());

	private final List<HandlerMethodArgumentResolver> argumentResolvers = new LinkedList<>();

	private final Map<MethodParameter, HandlerMethodArgumentResolver> argumentResolverCache =
			new ConcurrentHashMap<>(256);


	/**
	 * Add the given {@link HandlerMethodArgumentResolver}.
	 */
	public HandlerMethodArgumentResolverComposite addResolver(
			HandlerMethodArgumentResolver resolver) {
		this.argumentResolvers.add(resolver);
		return this;
	}

	/**
	 * Add the given {@link HandlerMethodArgumentResolver HandlerMethodArgumentResolvers}.
	 *
	 * @since 4.3
	 */
	public HandlerMethodArgumentResolverComposite addResolvers(
			@Nullable HandlerMethodArgumentResolver... resolvers) {
		if (resolvers != null) {
			Collections.addAll(this.argumentResolvers, resolvers);
		}
		return this;
	}

	/**
	 * Add the given {@link HandlerMethodArgumentResolver HandlerMethodArgumentResolvers}.
	 */
	public HandlerMethodArgumentResolverComposite addResolvers(
			@Nullable List<? extends HandlerMethodArgumentResolver> resolvers) {

		if (resolvers != null) {
			this.argumentResolvers.addAll(resolvers);
		}
		return this;
	}

	/**
	 * Return a read-only list with the contained resolvers, or an empty list.
	 */
	public List<HandlerMethodArgumentResolver> getResolvers() {
		return Collections.unmodifiableList(this.argumentResolvers);
	}

	/**
	 * Clear the list of configured resolvers.
	 *
	 * @since 4.3
	 */
	public void clear() {
		this.argumentResolvers.clear();
	}


	/**
	 * Whether the given {@linkplain MethodParameter method parameter} is
	 * supported by any registered {@link HandlerMethodArgumentResolver}.
	 */
	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return getArgumentResolver(parameter) != null;
	}

	/**
	 * 参数解析器处理请求参数
	 * Iterate over registered
	 * {@link HandlerMethodArgumentResolver HandlerMethodArgumentResolvers} and
	 * invoke the one that supports it.
	 *
	 * @throws IllegalStateException if no suitable
	 * {@link HandlerMethodArgumentResolver} is found.
	 */
	@Override
	@Nullable
	public Object resolveArgument(MethodParameter parameter,
			@Nullable ModelAndViewContainer mavContainer,
			NativeWebRequest webRequest, @Nullable WebDataBinderFactory binderFactory)
			throws Exception {

		//获取参数对应的参数解析器
		HandlerMethodArgumentResolver resolver = getArgumentResolver(parameter);
		if (resolver == null) {
			throw new IllegalArgumentException(
					"Unsupported parameter type [" + parameter.getParameterType().getName() + "]." +
							" supportsParameter should be called first.");
		}
		//参数解析，自定义参数解析需要自己实现的方法
		return resolver.resolveArgument(parameter, mavContainer, webRequest, binderFactory);
	}

	/**
	 * 获取parameter参数对应的参数解析器
	 * Find a registered {@link HandlerMethodArgumentResolver} that supports
	 * the given method parameter.
	 */
	@Nullable
	private HandlerMethodArgumentResolver getArgumentResolver(MethodParameter parameter) {
		//从缓存中查看有没有
		HandlerMethodArgumentResolver result = this.argumentResolverCache.get(parameter);
		if (result == null) {
			//缓存中没有，遍历所有的解析器
			for (HandlerMethodArgumentResolver methodArgumentResolver : this.argumentResolvers) {
				//判断是否支持，如果自定义话，这里就是一个用户需要实现的方法
				if (methodArgumentResolver.supportsParameter(parameter)) {
					//支持该解析器就是目标解析器
					result = methodArgumentResolver;
					//放入缓存
					this.argumentResolverCache.put(parameter, result);
					//不需要再继续了
					break;
				}
			}
		}
		return result;
	}

}
