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

package org.springframework.web.servlet.handler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.lang.Nullable;
import org.springframework.util.ObjectUtils;
import org.springframework.util.PathMatcher;
import org.springframework.web.context.request.WebRequestInterceptor;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

/**
 * 提供根据请求路径是否满足某些规则来应用拦截的拦截器，对应的spring mvc xml配置如下<p></p>
 * {@code
 * 	<mvc:interceptors>
 *     <mvc:interceptor>
 *         <mvc:mapping path="/interceptor/**" />
 *         <mvc:exclude-mapping path="/interceptor/b/*" />
 *         <bean class="com.elim.learn.spring.mvc.interceptor.MyInterceptor" />
 *     </mvc:interceptor>
 * </mvc:interceptors>
 * }
 * Contains and delegates calls to a {@link HandlerInterceptor} along with
 * include (and optionally exclude) path patterns to which the interceptor should apply.
 * Also provides matching logic to test if the interceptor applies to a given request path.
 *
 * <p>A MappedInterceptor can be registered directly with any
 * {@link org.springframework.web.servlet.handler.AbstractHandlerMethodMapping}.
 * Furthermore, beans of type {@code MappedInterceptor} are automatically detected by
 * {@code AbstractHandlerMethodMapping} (including ancestor ApplicationContext's) which
 * effectively means the interceptor is registered "globally" with all handler mappings.
 *
 * @author Keith Donald
 * @author Rossen Stoyanchev
 * @author Brian Clozel
 * @since 3.0
 */
public final class MappedInterceptor implements HandlerInterceptor {

	@Nullable
	//匹配的路径模式
	private final String[] includePatterns;

	@Nullable
	//排除的路径模式
	private final String[] excludePatterns;
	//包装的拦截器
	private final HandlerInterceptor interceptor;

	@Nullable
	//路径匹配器
	private PathMatcher pathMatcher;


	/**
	 * Create a new MappedInterceptor instance.
	 * @param includePatterns the path patterns to map (empty for matching to all paths)
	 * @param interceptor the HandlerInterceptor instance to map to the given patterns
	 */
	public MappedInterceptor(@Nullable String[] includePatterns, HandlerInterceptor interceptor) {
		this(includePatterns, null, interceptor);
	}

	/**
	 * Create a new MappedInterceptor instance.
	 * @param includePatterns the path patterns to map (empty for matching to all paths)
	 * @param excludePatterns the path patterns to exclude (empty for no specific excludes)
	 * @param interceptor the HandlerInterceptor instance to map to the given patterns
	 */
	public MappedInterceptor(@Nullable String[] includePatterns, @Nullable String[] excludePatterns,
			HandlerInterceptor interceptor) {

		this.includePatterns = includePatterns;
		this.excludePatterns = excludePatterns;
		this.interceptor = interceptor;
	}


	/**
	 * Create a new MappedInterceptor instance.
	 * @param includePatterns the path patterns to map (empty for matching to all paths)
	 * @param interceptor the WebRequestInterceptor instance to map to the given patterns
	 */
	public MappedInterceptor(@Nullable String[] includePatterns, WebRequestInterceptor interceptor) {
		this(includePatterns, null, interceptor);
	}

	/**
	 * Create a new MappedInterceptor instance.
	 * @param includePatterns the path patterns to map (empty for matching to all paths)
	 * @param excludePatterns the path patterns to exclude (empty for no specific excludes)
	 * @param interceptor the WebRequestInterceptor instance to map to the given patterns
	 */
	public MappedInterceptor(@Nullable String[] includePatterns, @Nullable String[] excludePatterns,
			WebRequestInterceptor interceptor) {

		this(includePatterns, excludePatterns, new WebRequestHandlerInterceptorAdapter(interceptor));
	}


	/**
	 * Configure a PathMatcher to use with this MappedInterceptor instead of the one passed
	 * by default to the {@link #matches(String, org.springframework.util.PathMatcher)} method.
	 * <p>This is an advanced property that is only required when using custom PathMatcher
	 * implementations that support mapping metadata other than the Ant-style path patterns
	 * supported by default.
	 */
	public void setPathMatcher(@Nullable PathMatcher pathMatcher) {
		this.pathMatcher = pathMatcher;
	}

	/**
	 * The configured PathMatcher, or {@code null} if none.
	 */
	@Nullable
	public PathMatcher getPathMatcher() {
		return this.pathMatcher;
	}

	/**
	 * The path into the application the interceptor is mapped to.
	 */
	@Nullable
	public String[] getPathPatterns() {
		return this.includePatterns;
	}

	/**
	 * The actual {@link HandlerInterceptor} reference.
	 */
	public HandlerInterceptor getInterceptor() {
		return this.interceptor;
	}


	/**
	 * 判断请求路径lookupPath是否和成员变量定义的includePatterns和excludePatterns中定义的规则匹配，
	 * 而匹配这件事有匹配器pathMatcher来计算
	 * <p/>
	 * Determine a match for the given lookup path.
	 * @param lookupPath the current request path
	 * @param pathMatcher a path matcher for path pattern matching
	 * @return {@code true} if the interceptor applies to the given request path
	 */
	public boolean matches(String lookupPath, PathMatcher pathMatcher) {
		PathMatcher pathMatcherToUse = (this.pathMatcher != null ? this.pathMatcher : pathMatcher);
		//如果存在需要排除的路径模式
		if (!ObjectUtils.isEmpty(this.excludePatterns)) {
			for (String pattern : this.excludePatterns) {
				//每一个要排除的路径模式都需要计算，有一个命中就排除
				if (pathMatcherToUse.match(pattern, lookupPath)) {
					return false;
				}
			}
		}
		//如果没有配置includePatterns，就是除了excludePatterns剩下的都包含
		if (ObjectUtils.isEmpty(this.includePatterns)) {
			return true;
		}
		//只有匹配上includePatterns的请求才拦截
		for (String pattern : this.includePatterns) {
			if (pathMatcherToUse.match(pattern, lookupPath)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
			throws Exception {

		return this.interceptor.preHandle(request, response, handler);
	}

	@Override
	public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
			@Nullable ModelAndView modelAndView) throws Exception {

		this.interceptor.postHandle(request, response, handler, modelAndView);
	}

	@Override
	public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler,
			@Nullable Exception ex) throws Exception {

		this.interceptor.afterCompletion(request, response, handler, ex);
	}

}
