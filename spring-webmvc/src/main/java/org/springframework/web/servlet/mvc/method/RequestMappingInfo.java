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

package org.springframework.web.servlet.mvc.method;

import java.util.List;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.util.PathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.accept.ContentNegotiationManager;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.condition.ConsumesRequestCondition;
import org.springframework.web.servlet.mvc.condition.HeadersRequestCondition;
import org.springframework.web.servlet.mvc.condition.ParamsRequestCondition;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.ProducesRequestCondition;
import org.springframework.web.servlet.mvc.condition.RequestCondition;
import org.springframework.web.servlet.mvc.condition.RequestConditionHolder;
import org.springframework.web.servlet.mvc.condition.RequestMethodsRequestCondition;
import org.springframework.web.util.UrlPathHelper;

/**
 * {@code @RequestMapping}对应的类
 * Request mapping information. Encapsulates the following request mapping conditions:
 * <ol>
 * <li>{@link PatternsRequestCondition}
 * <li>{@link RequestMethodsRequestCondition}
 * <li>{@link ParamsRequestCondition}
 * <li>{@link HeadersRequestCondition}
 * <li>{@link ConsumesRequestCondition}
 * <li>{@link ProducesRequestCondition}
 * <li>{@code RequestCondition} (optional, custom request condition)
 * </ol>
 *
 * @author Arjen Poutsma
 * @author Rossen Stoyanchev
 * @since 3.1
 */
public final class RequestMappingInfo implements RequestCondition<RequestMappingInfo> {

	@Nullable
	//Mapping的名称
	private final String name;
	/**
	 * 下面每一个匹配条件基本和{@code @RequestMapping}中的可以配置属性一一对应
	 */
	//请求路径匹配条件
	private final PatternsRequestCondition patternsCondition;
	//请求方法匹配条件
	private final RequestMethodsRequestCondition methodsCondition;
	//请求参数匹配条件
	private final ParamsRequestCondition paramsCondition;
	//请求头匹配条件
	private final HeadersRequestCondition headersCondition;
	//接收的Content-Type条件
	private final ConsumesRequestCondition consumesCondition;
	//产生的Content-Type条件
	private final ProducesRequestCondition producesCondition;
	//自定义请求条件
	private final RequestConditionHolder customConditionHolder;

	public RequestMappingInfo(@Nullable String name, @Nullable PatternsRequestCondition patterns,
							  @Nullable RequestMethodsRequestCondition methods, @Nullable ParamsRequestCondition params,
							  @Nullable HeadersRequestCondition headers, @Nullable ConsumesRequestCondition consumes,
							  @Nullable ProducesRequestCondition produces, @Nullable RequestCondition<?> custom) {

		this.name = (StringUtils.hasText(name) ? name : null);
		this.patternsCondition = (patterns != null ? patterns : new PatternsRequestCondition());
		this.methodsCondition = (methods != null ? methods : new RequestMethodsRequestCondition());
		this.paramsCondition = (params != null ? params : new ParamsRequestCondition());
		this.headersCondition = (headers != null ? headers : new HeadersRequestCondition());
		this.consumesCondition = (consumes != null ? consumes : new ConsumesRequestCondition());
		this.producesCondition = (produces != null ? produces : new ProducesRequestCondition());
		this.customConditionHolder = new RequestConditionHolder(custom);
	}

	/**
	 * Creates a new instance with the given request conditions.
	 */
	public RequestMappingInfo(@Nullable PatternsRequestCondition patterns,
							  @Nullable RequestMethodsRequestCondition methods, @Nullable ParamsRequestCondition params,
							  @Nullable HeadersRequestCondition headers, @Nullable ConsumesRequestCondition consumes,
							  @Nullable ProducesRequestCondition produces, @Nullable RequestCondition<?> custom) {

		this(null, patterns, methods, params, headers, consumes, produces, custom);
	}

	/**
	 * Re-create a RequestMappingInfo with the given custom request condition.
	 */
	public RequestMappingInfo(RequestMappingInfo info, @Nullable RequestCondition<?> customRequestCondition) {
		this(info.name, info.patternsCondition, info.methodsCondition, info.paramsCondition, info.headersCondition,
				info.consumesCondition, info.producesCondition, customRequestCondition);
	}

	/**
	 * Return the name for this mapping, or {@code null}.
	 */
	@Nullable
	public String getName() {
		return this.name;
	}

	/**
	 * Return the URL patterns of this {@link RequestMappingInfo};
	 * or instance with 0 patterns (never {@code null}).
	 */
	public PatternsRequestCondition getPatternsCondition() {
		return this.patternsCondition;
	}

	/**
	 * Return the HTTP request methods of this {@link RequestMappingInfo};
	 * or instance with 0 request methods (never {@code null}).
	 */
	public RequestMethodsRequestCondition getMethodsCondition() {
		return this.methodsCondition;
	}

	/**
	 * Return the "parameters" condition of this {@link RequestMappingInfo};
	 * or instance with 0 parameter expressions (never {@code null}).
	 */
	public ParamsRequestCondition getParamsCondition() {
		return this.paramsCondition;
	}

	/**
	 * Return the "headers" condition of this {@link RequestMappingInfo};
	 * or instance with 0 header expressions (never {@code null}).
	 */
	public HeadersRequestCondition getHeadersCondition() {
		return this.headersCondition;
	}

	/**
	 * Return the "consumes" condition of this {@link RequestMappingInfo};
	 * or instance with 0 consumes expressions (never {@code null}).
	 */
	public ConsumesRequestCondition getConsumesCondition() {
		return this.consumesCondition;
	}

	/**
	 * Return the "produces" condition of this {@link RequestMappingInfo};
	 * or instance with 0 produces expressions (never {@code null}).
	 */
	public ProducesRequestCondition getProducesCondition() {
		return this.producesCondition;
	}

	/**
	 * Return the "custom" condition of this {@link RequestMappingInfo}, or {@code null}.
	 */
	@Nullable
	public RequestCondition<?> getCustomCondition() {
		return this.customConditionHolder.getCondition();
	}

	/**
	 * 将当前RequestMappingInfo和另一个RequestMappingInfo信息进行融合，多见于类上{@code @RequestMapping}和方法上{@code @RequestMapping}的融合
	 * <p></p>
	 * Combine "this" request mapping info (i.e. the current instance) with another request mapping info instance.
	 * <p>Example: combine type- and method-level request mappings.
	 *
	 * @return a new request mapping info instance; never {@code null}
	 */
	@Override
	public RequestMappingInfo combine(RequestMappingInfo other) {
		//融合名称  类注解的名称#方法注解的名称
		String name = combineNames(other);
		//各种匹配条件模式融合
		PatternsRequestCondition patterns = this.patternsCondition.combine(other.patternsCondition);
		RequestMethodsRequestCondition methods = this.methodsCondition.combine(other.methodsCondition);
		ParamsRequestCondition params = this.paramsCondition.combine(other.paramsCondition);
		HeadersRequestCondition headers = this.headersCondition.combine(other.headersCondition);
		ConsumesRequestCondition consumes = this.consumesCondition.combine(other.consumesCondition);
		ProducesRequestCondition produces = this.producesCondition.combine(other.producesCondition);
		RequestConditionHolder custom = this.customConditionHolder.combine(other.customConditionHolder);
		//创建融合后的RequestMappingInfo
		return new RequestMappingInfo(name, patterns,
				methods, params, headers, consumes, produces, custom.getCondition());
	}

	@Nullable
	private String combineNames(RequestMappingInfo other) {
		if (this.name != null && other.name != null) {
			String separator = RequestMappingInfoHandlerMethodMappingNamingStrategy.SEPARATOR;
			return this.name + separator + other.name;
		} else if (this.name != null) {
			return this.name;
		} else {
			return other.name;
		}
	}

	/**
	 * 使用类中各种匹配条件对请求进行匹配，相当于用{@code @RequestMapping}中解析出的RequestMappingInfo，去匹配当前请求是不是请求的就是RequestMapping对应的类、对应的方法
	 * <p></p>
	 * Checks if all conditions in this request mapping info match the provided request and returns
	 * a potentially new request mapping info with conditions tailored to the current request.
	 * <p>For example the returned instance may contain the subset of URL patterns that match to
	 * the current request, sorted with best matching patterns on top.
	 *
	 * @return a new instance in case all conditions match; or {@code null} otherwise
	 */
	@Override
	@Nullable
	public RequestMappingInfo getMatchingCondition(HttpServletRequest request) {
		//进行方法、参数、请求头、Content-Type的匹配
		RequestMethodsRequestCondition methods = this.methodsCondition.getMatchingCondition(request);
		ParamsRequestCondition params = this.paramsCondition.getMatchingCondition(request);
		HeadersRequestCondition headers = this.headersCondition.getMatchingCondition(request);
		ConsumesRequestCondition consumes = this.consumesCondition.getMatchingCondition(request);
		ProducesRequestCondition produces = this.producesCondition.getMatchingCondition(request);

		//只要有任何一个为空，说明没有匹配上，返回null
		if (methods == null || params == null || headers == null || consumes == null || produces == null) {
			return null;
		}
		//进行路径的匹配
		PatternsRequestCondition patterns = this.patternsCondition.getMatchingCondition(request);
		if (patterns == null) {
			return null;
		}
		//进行自定义条件的匹配
		RequestConditionHolder custom = this.customConditionHolder.getMatchingCondition(request);
		if (custom == null) {
			return null;
		}
		//将匹配项的各个属性封装成新的RequestMappingInfo返回
		/**
		 * 为什么要重新创建一个RequestMappingInfo是因为，第一次RequestMappingInfo的创建时解析了{@code @RequestMapping}
		 * 注解中的信息，那么{@code @RequestMapping}中的属性完全可能配置多个，比如多个uri映射，但是这里的RequestMappingInfo
		 * 是和当前request一一对应的，一个request的属性基本都是唯一的，所以要创建一个新的，解析{@code RequestMapping}并构建
		 * RequestMappingInfo对象的过程在RequestMappingHandlerMapping#createRequestMappingInfo
		 */
		return new RequestMappingInfo(this.name, patterns,
				methods, params, headers, consumes, produces, custom.getCondition());
	}

	/**
	 * 多个RequestMappingInfo的排序规则
	 * Compares "this" info (i.e. the current instance) with another info in the context of a request.
	 * <p>Note: It is assumed both instances have been obtained via
	 * {@link #getMatchingCondition(HttpServletRequest)} to ensure they have conditions with
	 * content relevant to current request.
	 */
	@Override
	public int compareTo(RequestMappingInfo other, HttpServletRequest request) {
		int result;
		// Automatic vs explicit HTTP HEAD mapping
		//如果是HEAD请求
		if (HttpMethod.HEAD.matches(request.getMethod())) {
			//按照methodCondition的比较规则比较
			result = this.methodsCondition.compareTo(other.getMethodsCondition(), request);
			if (result != 0) {
				return result;
			}
		}
		//其他请求按照patternsCondition、paramsCondition、headersCondition、consumesCondition等顺序依次比较
		result = this.patternsCondition.compareTo(other.getPatternsCondition(), request);
		if (result != 0) {
			return result;
		}
		result = this.paramsCondition.compareTo(other.getParamsCondition(), request);
		if (result != 0) {
			return result;
		}
		result = this.headersCondition.compareTo(other.getHeadersCondition(), request);
		if (result != 0) {
			return result;
		}
		result = this.consumesCondition.compareTo(other.getConsumesCondition(), request);
		if (result != 0) {
			return result;
		}
		result = this.producesCondition.compareTo(other.getProducesCondition(), request);
		if (result != 0) {
			return result;
		}
		// Implicit (no method) vs explicit HTTP method mappings
		result = this.methodsCondition.compareTo(other.getMethodsCondition(), request);
		if (result != 0) {
			return result;
		}
		result = this.customConditionHolder.compareTo(other.customConditionHolder, request);
		if (result != 0) {
			return result;
		}
		return 0;
	}

	@Override
	public boolean equals(Object other) {
		if (this == other) {
			return true;
		}
		if (!(other instanceof RequestMappingInfo)) {
			return false;
		}
		RequestMappingInfo otherInfo = (RequestMappingInfo) other;
		return (this.patternsCondition.equals(otherInfo.patternsCondition) &&
				this.methodsCondition.equals(otherInfo.methodsCondition) &&
				this.paramsCondition.equals(otherInfo.paramsCondition) &&
				this.headersCondition.equals(otherInfo.headersCondition) &&
				this.consumesCondition.equals(otherInfo.consumesCondition) &&
				this.producesCondition.equals(otherInfo.producesCondition) &&
				this.customConditionHolder.equals(otherInfo.customConditionHolder));
	}

	@Override
	public int hashCode() {
		return (this.patternsCondition.hashCode() * 31 +  // primary differentiation
				this.methodsCondition.hashCode() + this.paramsCondition.hashCode() +
				this.headersCondition.hashCode() + this.consumesCondition.hashCode() +
				this.producesCondition.hashCode() + this.customConditionHolder.hashCode());
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder("{");
		if (!this.methodsCondition.isEmpty()) {
			Set<RequestMethod> httpMethods = this.methodsCondition.getMethods();
			builder.append(httpMethods.size() == 1 ? httpMethods.iterator().next() : httpMethods);
		}
		if (!this.patternsCondition.isEmpty()) {
			Set<String> patterns = this.patternsCondition.getPatterns();
			builder.append(" ").append(patterns.size() == 1 ? patterns.iterator().next() : patterns);
		}
		if (!this.paramsCondition.isEmpty()) {
			builder.append(", params ").append(this.paramsCondition);
		}
		if (!this.headersCondition.isEmpty()) {
			builder.append(", headers ").append(this.headersCondition);
		}
		if (!this.consumesCondition.isEmpty()) {
			builder.append(", consumes ").append(this.consumesCondition);
		}
		if (!this.producesCondition.isEmpty()) {
			builder.append(", produces ").append(this.producesCondition);
		}
		if (!this.customConditionHolder.isEmpty()) {
			builder.append(", and ").append(this.customConditionHolder);
		}
		builder.append('}');
		return builder.toString();
	}

	/**
	 * Create a new {@code RequestMappingInfo.Builder} with the given paths.
	 *
	 * @param paths the paths to use
	 * @since 4.2
	 */
	public static Builder paths(String... paths) {
		return new DefaultBuilder(paths);
	}

	/**
	 * Defines a builder for creating a RequestMappingInfo.
	 *
	 * @since 4.2
	 */
	public interface Builder {

		/**
		 * Set the path patterns.
		 */
		Builder paths(String... paths);

		/**
		 * Set the request method conditions.
		 */
		Builder methods(RequestMethod... methods);

		/**
		 * Set the request param conditions.
		 */
		Builder params(String... params);

		/**
		 * Set the header conditions.
		 * <p>By default this is not set.
		 */
		Builder headers(String... headers);

		/**
		 * Set the consumes conditions.
		 */
		Builder consumes(String... consumes);

		/**
		 * Set the produces conditions.
		 */
		Builder produces(String... produces);

		/**
		 * Set the mapping name.
		 */
		Builder mappingName(String name);

		/**
		 * Set a custom condition to use.
		 */
		Builder customCondition(RequestCondition<?> condition);

		/**
		 * Provide additional configuration needed for request mapping purposes.
		 */
		Builder options(BuilderConfiguration options);

		/**
		 * Build the RequestMappingInfo.
		 */
		RequestMappingInfo build();
	}

	private static class DefaultBuilder implements Builder {

		private String[] paths = new String[0];

		private RequestMethod[] methods = new RequestMethod[0];

		private String[] params = new String[0];

		private String[] headers = new String[0];

		private String[] consumes = new String[0];

		private String[] produces = new String[0];

		@Nullable
		private String mappingName;

		@Nullable
		private RequestCondition<?> customCondition;

		private BuilderConfiguration options = new BuilderConfiguration();

		public DefaultBuilder(String... paths) {
			this.paths = paths;
		}

		@Override
		public Builder paths(String... paths) {
			this.paths = paths;
			return this;
		}

		@Override
		public DefaultBuilder methods(RequestMethod... methods) {
			this.methods = methods;
			return this;
		}

		@Override
		public DefaultBuilder params(String... params) {
			this.params = params;
			return this;
		}

		@Override
		public DefaultBuilder headers(String... headers) {
			this.headers = headers;
			return this;
		}

		@Override
		public DefaultBuilder consumes(String... consumes) {
			this.consumes = consumes;
			return this;
		}

		@Override
		public DefaultBuilder produces(String... produces) {
			this.produces = produces;
			return this;
		}

		@Override
		public DefaultBuilder mappingName(String name) {
			this.mappingName = name;
			return this;
		}

		@Override
		public DefaultBuilder customCondition(RequestCondition<?> condition) {
			this.customCondition = condition;
			return this;
		}

		@Override
		public Builder options(BuilderConfiguration options) {
			this.options = options;
			return this;
		}

		@Override
		public RequestMappingInfo build() {
			ContentNegotiationManager manager = this.options.getContentNegotiationManager();

			PatternsRequestCondition patternsCondition = new PatternsRequestCondition(
					this.paths, this.options.getUrlPathHelper(), this.options.getPathMatcher(),
					this.options.useSuffixPatternMatch(), this.options.useTrailingSlashMatch(),
					this.options.getFileExtensions());

			return new RequestMappingInfo(this.mappingName, patternsCondition,
					new RequestMethodsRequestCondition(this.methods),
					new ParamsRequestCondition(this.params),
					new HeadersRequestCondition(this.headers),
					new ConsumesRequestCondition(this.consumes, this.headers),
					new ProducesRequestCondition(this.produces, this.headers, manager),
					this.customCondition);
		}
	}

	/**
	 * Container for configuration options used for request mapping purposes.
	 * Such configuration is required to create RequestMappingInfo instances but
	 * is typically used across all RequestMappingInfo instances.
	 *
	 * @see Builder#options
	 * @since 4.2
	 */
	public static class BuilderConfiguration {

		@Nullable
		private UrlPathHelper urlPathHelper;

		@Nullable
		private PathMatcher pathMatcher;

		private boolean trailingSlashMatch = true;

		private boolean suffixPatternMatch = true;

		private boolean registeredSuffixPatternMatch = false;

		@Nullable
		private ContentNegotiationManager contentNegotiationManager;

		/**
		 * Set a custom UrlPathHelper to use for the PatternsRequestCondition.
		 * <p>By default this is not set.
		 *
		 * @since 4.2.8
		 */
		public void setUrlPathHelper(@Nullable UrlPathHelper urlPathHelper) {
			this.urlPathHelper = urlPathHelper;
		}

		/**
		 * Return a custom UrlPathHelper to use for the PatternsRequestCondition, if any.
		 */
		@Nullable
		public UrlPathHelper getUrlPathHelper() {
			return this.urlPathHelper;
		}

		/**
		 * Set a custom PathMatcher to use for the PatternsRequestCondition.
		 * <p>By default this is not set.
		 */
		public void setPathMatcher(@Nullable PathMatcher pathMatcher) {
			this.pathMatcher = pathMatcher;
		}

		/**
		 * Return a custom PathMatcher to use for the PatternsRequestCondition, if any.
		 */
		@Nullable
		public PathMatcher getPathMatcher() {
			return this.pathMatcher;
		}

		/**
		 * Set whether to apply trailing slash matching in PatternsRequestCondition.
		 * <p>By default this is set to 'true'.
		 */
		public void setTrailingSlashMatch(boolean trailingSlashMatch) {
			this.trailingSlashMatch = trailingSlashMatch;
		}

		/**
		 * Return whether to apply trailing slash matching in PatternsRequestCondition.
		 */
		public boolean useTrailingSlashMatch() {
			return this.trailingSlashMatch;
		}

		/**
		 * Set whether to apply suffix pattern matching in PatternsRequestCondition.
		 * <p>By default this is set to 'true'.
		 *
		 * @see #setRegisteredSuffixPatternMatch(boolean)
		 */
		public void setSuffixPatternMatch(boolean suffixPatternMatch) {
			this.suffixPatternMatch = suffixPatternMatch;
		}

		/**
		 * Return whether to apply suffix pattern matching in PatternsRequestCondition.
		 */
		public boolean useSuffixPatternMatch() {
			return this.suffixPatternMatch;
		}

		/**
		 * Set whether suffix pattern matching should be restricted to registered
		 * file extensions only. Setting this property also sets
		 * {@code suffixPatternMatch=true} and requires that a
		 * {@link #setContentNegotiationManager} is also configured in order to
		 * obtain the registered file extensions.
		 */
		public void setRegisteredSuffixPatternMatch(boolean registeredSuffixPatternMatch) {
			this.registeredSuffixPatternMatch = registeredSuffixPatternMatch;
			this.suffixPatternMatch = (registeredSuffixPatternMatch || this.suffixPatternMatch);
		}

		/**
		 * Return whether suffix pattern matching should be restricted to registered
		 * file extensions only.
		 */
		public boolean useRegisteredSuffixPatternMatch() {
			return this.registeredSuffixPatternMatch;
		}

		/**
		 * Return the file extensions to use for suffix pattern matching. If
		 * {@code registeredSuffixPatternMatch=true}, the extensions are obtained
		 * from the configured {@code contentNegotiationManager}.
		 */
		@Nullable
		public List<String> getFileExtensions() {
			if (useRegisteredSuffixPatternMatch() && this.contentNegotiationManager != null) {
				return this.contentNegotiationManager.getAllFileExtensions();
			}
			return null;
		}

		/**
		 * Set the ContentNegotiationManager to use for the ProducesRequestCondition.
		 * <p>By default this is not set.
		 */
		public void setContentNegotiationManager(ContentNegotiationManager contentNegotiationManager) {
			this.contentNegotiationManager = contentNegotiationManager;
		}

		/**
		 * Return the ContentNegotiationManager to use for the ProducesRequestCondition,
		 * if any.
		 */
		@Nullable
		public ContentNegotiationManager getContentNegotiationManager() {
			return this.contentNegotiationManager;
		}
	}

}
