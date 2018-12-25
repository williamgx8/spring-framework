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

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;
import java.util.stream.Collectors;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.MethodIntrospector;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerMapping;

/**
 * Abstract base class for {@link HandlerMapping} implementations that define
 * a mapping between a request and a {@link HandlerMethod}.
 *
 * <p>For each registered handler method, a unique mapping is maintained with
 * subclasses defining the details of the mapping type {@code <T>}.
 *
 * @param <T> the mapping for a {@link HandlerMethod} containing the conditions
 * needed to match the handler method to incoming request.
 * @author Arjen Poutsma
 * @author Rossen Stoyanchev
 * @author Juergen Hoeller
 * @since 3.1
 */
public abstract class AbstractHandlerMethodMapping<T> extends AbstractHandlerMapping implements
		InitializingBean {

	/**
	 * Bean name prefix for target beans behind scoped proxies. Used to exclude those
	 * targets from handler method detection, in favor of the corresponding proxies.
	 * <p>We're not checking the autowire-candidate status here, which is how the
	 * proxy target filtering problem is being handled at the autowiring level,
	 * since autowire-candidate may have been turned to {@code false} for other
	 * reasons, while still expecting the bean to be eligible for handler methods.
	 * <p>Originally defined in {@link org.springframework.aop.scope.ScopedProxyUtils}
	 * but duplicated here to avoid a hard dependency on the spring-aop module.
	 */
	private static final String SCOPED_TARGET_NAME_PREFIX = "scopedTarget.";

	private static final HandlerMethod PREFLIGHT_AMBIGUOUS_MATCH =
			new HandlerMethod(new EmptyHandler(),
					ClassUtils.getMethod(EmptyHandler.class, "handle"));

	private static final CorsConfiguration ALLOW_CORS_CONFIG = new CorsConfiguration();

	static {
		ALLOW_CORS_CONFIG.addAllowedOrigin("*");
		ALLOW_CORS_CONFIG.addAllowedMethod("*");
		ALLOW_CORS_CONFIG.addAllowedHeader("*");
		ALLOW_CORS_CONFIG.setAllowCredentials(true);
	}


	private boolean detectHandlerMethodsInAncestorContexts = false;

	@Nullable
	//Mapping命名策略
	private HandlerMethodMappingNamingStrategy<T> namingStrategy;
	//Mapping注册表
	private final MappingRegistry mappingRegistry = new MappingRegistry();


	/**
	 * Whether to detect handler methods in beans in ancestor ApplicationContexts.
	 * <p>Default is "false": Only beans in the current ApplicationContext are
	 * considered, i.e. only in the context that this HandlerMapping itself
	 * is defined in (typically the current DispatcherServlet's context).
	 * <p>Switch this flag on to detect handler beans in ancestor contexts
	 * (typically the Spring root WebApplicationContext) as well.
	 *
	 * @see #getCandidateBeanNames()
	 */
	public void setDetectHandlerMethodsInAncestorContexts(
			boolean detectHandlerMethodsInAncestorContexts) {
		this.detectHandlerMethodsInAncestorContexts = detectHandlerMethodsInAncestorContexts;
	}

	/**
	 * Configure the naming strategy to use for assigning a default name to every
	 * mapped handler method.
	 * <p>The default naming strategy is based on the capital letters of the
	 * class name followed by "#" and then the method name, e.g. "TC#getFoo"
	 * for a class named TestController with method getFoo.
	 */
	public void setHandlerMethodMappingNamingStrategy(
			HandlerMethodMappingNamingStrategy<T> namingStrategy) {
		this.namingStrategy = namingStrategy;
	}

	/**
	 * Return the configured naming strategy or {@code null}.
	 */
	@Nullable
	public HandlerMethodMappingNamingStrategy<T> getNamingStrategy() {
		return this.namingStrategy;
	}

	/**
	 * Return a (read-only) map with all mappings and HandlerMethod's.
	 */
	public Map<T, HandlerMethod> getHandlerMethods() {
		this.mappingRegistry.acquireReadLock();
		try {
			return Collections.unmodifiableMap(this.mappingRegistry.getMappings());
		} finally {
			this.mappingRegistry.releaseReadLock();
		}
	}

	/**
	 * Return the handler methods for the given mapping name.
	 *
	 * @param mappingName the mapping name
	 * @return a list of matching HandlerMethod's or {@code null}; the returned
	 * list will never be modified and is safe to iterate.
	 * @see #setHandlerMethodMappingNamingStrategy
	 */
	@Nullable
	public List<HandlerMethod> getHandlerMethodsForMappingName(String mappingName) {
		return this.mappingRegistry.getHandlerMethodsByMappingName(mappingName);
	}

	/**
	 * Return the internal mapping registry. Provided for testing purposes.
	 */
	MappingRegistry getMappingRegistry() {
		return this.mappingRegistry;
	}

	/**
	 * Register the given mapping.
	 * <p>This method may be invoked at runtime after initialization has completed.
	 *
	 * @param mapping the mapping for the handler method
	 * @param handler the handler
	 * @param method the method
	 */
	public void registerMapping(T mapping, Object handler, Method method) {
		if (logger.isTraceEnabled()) {
			logger.trace("Register \"" + mapping + "\" to " + method.toGenericString());
		}
		this.mappingRegistry.register(mapping, handler, method);
	}

	/**
	 * Un-register the given mapping.
	 * <p>This method may be invoked at runtime after initialization has completed.
	 *
	 * @param mapping the mapping to unregister
	 */
	public void unregisterMapping(T mapping) {
		if (logger.isTraceEnabled()) {
			logger.trace("Unregister mapping \"" + mapping + "\"");
		}
		this.mappingRegistry.unregister(mapping);
	}

	// Handler method detection

	/**
	 * Detects handler methods at initialization.
	 *
	 * @see #initHandlerMethods
	 */
	@Override
	public void afterPropertiesSet() {
		//初始化所有HandlerMethod
		initHandlerMethods();
	}

	/**
	 * Scan beans in the ApplicationContext, detect and register handler methods.
	 *
	 * @see #getCandidateBeanNames()
	 * @see #processCandidateBean
	 * @see #handlerMethodsInitialized
	 */
	protected void initHandlerMethods() {
		//获取所有候选bean的名称
		for (String beanName : getCandidateBeanNames()) {
			//只要不是以socpedTarget.开头
			if (!beanName.startsWith(SCOPED_TARGET_NAME_PREFIX)) {
				//处理候选bean
				processCandidateBean(beanName);
			}
		}
		//记录所有mappingLookup集合的数量，打印日志
		handlerMethodsInitialized(getHandlerMethods());
	}

	/**
	 * 获取容器中所有bean的名称数组
	 * Determine the names of candidate beans in the application context.
	 *
	 * @see #setDetectHandlerMethodsInAncestorContexts
	 * @see BeanFactoryUtils#beanNamesForTypeIncludingAncestors
	 * @since 5.1
	 */
	protected String[] getCandidateBeanNames() {
		//如果允许从父容器 root WebApplicationContext 中开始查找，就两个容器一起获取，否则只从spring mvc 的WebApplicationContext中获取所有bean名称
		return (this.detectHandlerMethodsInAncestorContexts ?
				BeanFactoryUtils.beanNamesForTypeIncludingAncestors(obtainApplicationContext(),
						Object.class) :
				obtainApplicationContext().getBeanNamesForType(Object.class));
	}

	/**
	 * 对于名称为beanName的Handler下可能的HandlerMethod进行筛选和处理
	 * <p></p>
	 * Determine the type of the specified candidate bean and call
	 * {@link #detectHandlerMethods} if identified as a handler type.
	 * <p>This implementation avoids bean creation through checking
	 * {@link org.springframework.beans.factory.BeanFactory#getType}
	 * and calling {@link #detectHandlerMethods} with the bean name.
	 *
	 * @param beanName the name of the candidate bean
	 * @see #isHandler
	 * @see #detectHandlerMethods
	 * @since 5.1
	 */
	protected void processCandidateBean(String beanName) {
		Class<?> beanType = null;
		try {
			//根据bean name获取bean type
			beanType = obtainApplicationContext().getType(beanName);
		} catch (Throwable ex) {
			// An unresolvable bean type, probably from a lazy bean - let's ignore it.
			if (logger.isTraceEnabled()) {
				logger.trace("Could not resolve type for bean '" + beanName + "'", ex);
			}
		}
		//判断是否是Handler处理器
		if (beanType != null && isHandler(beanType)) {
			//寻找其中的HandlerMethod
			detectHandlerMethods(beanName);
		}
	}

	/**
	 * 查找handler中的HandlerMethod
	 * Look for handler methods in the specified handler bean.
	 *
	 * @param handler either a bean name or an actual handler instance
	 * @see #getMappingForMethod
	 */
	protected void detectHandlerMethods(Object handler) {
		//如果是handler的名称，或者名称对应的类型，否则类型就是其本身
		Class<?> handlerType = (handler instanceof String ?
				obtainApplicationContext().getType((String) handler) : handler.getClass());

		if (handlerType != null) {
			//去掉动态代理的$$
			Class<?> userType = ClassUtils.getUserClass(handlerType);
			Map<Method, T> methods = MethodIntrospector.selectMethods(userType,
					(MethodIntrospector.MetadataLookup<T>) method -> {
						try {
							//获得method对应对的Mapping对象，对于@RequestMapping来说就是RequestMappingInfo
							return getMappingForMethod(method, userType);
						} catch (Throwable ex) {
							throw new IllegalStateException("Invalid mapping on handler class [" +
									userType.getName() + "]: " + method, ex);
						}
					});
			if (logger.isTraceEnabled()) {
				logger.trace(formatMappings(userType, methods));
			}
			//遍历每一组映射
			methods.forEach((method, mapping) -> {
				//从userType和其父类/接口中找到一个可以真正调用的method对象
				Method invocableMethod = AopUtils.selectInvocableMethod(method, userType);
				//各种映射关系的注册
				registerHandlerMethod(handler, invocableMethod, mapping);
			});
		}
	}

	private String formatMappings(Class<?> userType, Map<Method, T> methods) {

		String formattedType = Arrays.stream(userType.getPackage().getName().split("\\."))
				.map(p -> p.substring(0, 1))
				.collect(Collectors.joining(".", "", ".")) + userType.getSimpleName();

		Function<Method, String> methodFormatter = method -> Arrays
				.stream(method.getParameterTypes())
				.map(Class::getSimpleName)
				.collect(Collectors.joining(",", "(", ")"));

		return methods.entrySet().stream()
				.map(e -> {
					Method method = e.getKey();
					return e.getValue() + ": " + method.getName() + methodFormatter.apply(method);
				})
				.collect(Collectors.joining("\n\t", "\n\t" + formattedType + ":" + "\n\t", ""));
	}

	/**
	 * Register a handler method and its unique mapping. Invoked at startup for
	 * each detected handler method.
	 *
	 * @param handler the bean name of the handler or the handler instance
	 * @param method the method to register
	 * @param mapping the mapping conditions associated with the handler method
	 * @throws IllegalStateException if another method was already registered
	 * under the same mapping
	 */
	protected void registerHandlerMethod(Object handler, Method method, T mapping) {
		this.mappingRegistry.register(mapping, handler, method);
	}

	/**
	 * Create the HandlerMethod instance.
	 *
	 * @param handler either a bean name or an actual handler instance
	 * @param method the target method
	 * @return the created HandlerMethod
	 */
	protected HandlerMethod createHandlerMethod(Object handler, Method method) {
		HandlerMethod handlerMethod;
		//handler为字符串，说明传的是HandlerMethod的类名
		if (handler instanceof String) {
			String beanName = (String) handler;
			//封装成HandlerMethod，构造器内部会从spring中获得类名对应的类型
			handlerMethod = new HandlerMethod(beanName,
					obtainApplicationContext().getAutowireCapableBeanFactory(), method);
		} else {
			//handler就是HandlerMethod类型
			handlerMethod = new HandlerMethod(handler, method);
		}
		return handlerMethod;
	}

	/**
	 * Extract and return the CORS configuration for the mapping.
	 */
	@Nullable
	protected CorsConfiguration initCorsConfiguration(Object handler, Method method, T mapping) {
		return null;
	}

	/**
	 * Invoked after all handler methods have been detected.
	 *
	 * @param handlerMethods a read-only map with handler methods and mappings.
	 */
	protected void handlerMethodsInitialized(Map<T, HandlerMethod> handlerMethods) {
		// Total includes detected mappings + explicit registrations via registerMapping
		int total = handlerMethods.size();
		if ((logger.isTraceEnabled() && total == 0) || (logger.isDebugEnabled() && total > 0)) {
			logger.debug(total + " mappings in " + formatMappingName());
		}
	}

	// Handler method lookup

	/**
	 * 根据请求获取对应HandlerMethod
	 * Look up a handler method for the given request.
	 */
	@Override
	protected HandlerMethod getHandlerInternal(HttpServletRequest request) throws Exception {
		//获取完整的请求路径
		String lookupPath = getUrlPathHelper().getLookupPathForRequest(request);
		//获取读锁
		this.mappingRegistry.acquireReadLock();
		try {
			//查找请求路径最匹配的HandlerMethod
			HandlerMethod handlerMethod = lookupHandlerMethod(lookupPath, request);
			//确保HandlerMethod中bean属性的解析成功
			return (handlerMethod != null ? handlerMethod.createWithResolvedBean() : null);
		} finally {
			//释放读锁
			this.mappingRegistry.releaseReadLock();
		}
	}

	/**
	 * 查找请求路径对应的HandlerMethod
	 * Look up the best-matching handler method for the current request.
	 * If multiple matches are found, the best match is selected.
	 *
	 * @param lookupPath mapping lookup path within the current servlet mapping 请求的URI
	 * @param request the current request 请求对象
	 * @return the best-matching handler method, or {@code null} if no match
	 * @see #handleMatch(Object, String, HttpServletRequest)
	 * @see #handleNoMatch(Set, String, HttpServletRequest)
	 */
	@Nullable
	protected HandlerMethod lookupHandlerMethod(String lookupPath, HttpServletRequest request)
			throws Exception {
		//保存于当前请求匹配的结果
		List<Match> matches = new ArrayList<>();
		//根据请求路径找到与之匹配的所有Mapping
		List<T> directPathMatches = this.mappingRegistry.getMappingsByUrl(lookupPath);
		if (directPathMatches != null) {
			//将匹配内容放入封装成Match放入matches
			addMatchingMappings(directPathMatches, matches, request);
		}
		if (matches.isEmpty()) {
			// No choice but to go through all mappings...
			//没有找到，查找所有Mapping进行匹配
			addMatchingMappings(this.mappingRegistry.getMappings().keySet(), matches, request);
		}

		//找到匹配项进行排序
		if (!matches.isEmpty()) {
			//获得Mapping的比较器
			Comparator<Match> comparator = new MatchComparator(getMappingComparator(request));
			//排序
			matches.sort(comparator);
			//取出最匹配的一个
			Match bestMatch = matches.get(0);
			//存在多个匹配项
			if (matches.size() > 1) {
				if (logger.isTraceEnabled()) {
					logger.trace(matches.size() + " matching mappings: " + matches);
				}
				if (CorsUtils.isPreFlightRequest(request)) {
					return PREFLIGHT_AMBIGUOUS_MATCH;
				}
				//第二匹配项
				Match secondBestMatch = matches.get(1);
				//如果第一批配合第二匹配是相同等级的
				if (comparator.compare(bestMatch, secondBestMatch) == 0) {
					//取出两者对应的方法，报错
					Method m1 = bestMatch.handlerMethod.getMethod();
					Method m2 = secondBestMatch.handlerMethod.getMethod();
					String uri = request.getRequestURI();
					throw new IllegalStateException(
							"Ambiguous handler methods mapped for '" + uri + "': {" + m1 + ", " + m2
									+ "}");
				}
			}
			//将最匹配的HandlerMethod放入request属性中
			request.setAttribute(BEST_MATCHING_HANDLER_ATTRIBUTE, bestMatch.handlerMethod);
			//将Mapping与请求路径的映射放入request属性中
			handleMatch(bestMatch.mapping, lookupPath, request);
			//返回最匹配项HandlerMethod
			return bestMatch.handlerMethod;
		} else {
			//处理未匹配的情况
			return handleNoMatch(this.mappingRegistry.getMappings().keySet(), lookupPath, request);
		}
	}

	/**
	 * 从Mapping集合中找到与请求匹配的Mapping，包装成Match放入matches集合
	 * @param mappings Mapping集合
	 * @param matches 存放结果的Match列表
	 * @param request 请求对象
	 */
	private void addMatchingMappings(Collection<T> mappings, List<Match> matches,
			HttpServletRequest request) {
		//遍历所有的Mapping
		for (T mapping : mappings) {
			//筛选匹配的Mapping
			T match = getMatchingMapping(mapping, request);
			if (match != null) {
				//存在匹配项包装成Match放入集合
				matches.add(new Match(match, this.mappingRegistry.getMappings().get(mapping)));
			}
		}
	}

	/**
	 * Invoked when a matching mapping is found.
	 *
	 * @param mapping the matching mapping
	 * @param lookupPath mapping lookup path within the current servlet mapping
	 * @param request the current request
	 */
	protected void handleMatch(T mapping, String lookupPath, HttpServletRequest request) {
		request.setAttribute(HandlerMapping.PATH_WITHIN_HANDLER_MAPPING_ATTRIBUTE, lookupPath);
	}

	/**
	 * Invoked when no matching mapping is not found.
	 *
	 * @param mappings all registered mappings
	 * @param lookupPath mapping lookup path within the current servlet mapping
	 * @param request the current request
	 * @throws ServletException in case of errors
	 */
	@Nullable
	protected HandlerMethod handleNoMatch(Set<T> mappings, String lookupPath,
			HttpServletRequest request)
			throws Exception {

		return null;
	}

	@Override
	protected CorsConfiguration getCorsConfiguration(Object handler, HttpServletRequest request) {
		CorsConfiguration corsConfig = super.getCorsConfiguration(handler, request);
		if (handler instanceof HandlerMethod) {
			HandlerMethod handlerMethod = (HandlerMethod) handler;
			if (handlerMethod.equals(PREFLIGHT_AMBIGUOUS_MATCH)) {
				return AbstractHandlerMethodMapping.ALLOW_CORS_CONFIG;
			} else {
				CorsConfiguration corsConfigFromMethod = this.mappingRegistry
						.getCorsConfiguration(handlerMethod);
				corsConfig = (corsConfig != null ? corsConfig.combine(corsConfigFromMethod)
						: corsConfigFromMethod);
			}
		}
		return corsConfig;
	}

	// Abstract template methods

	/**
	 * Whether the given type is a handler with handler methods.
	 *
	 * @param beanType the type of the bean being checked
	 * @return "true" if this a handler type, "false" otherwise.
	 */
	protected abstract boolean isHandler(Class<?> beanType);

	/**
	 * Provide the mapping for a handler method. A method for which no
	 * mapping can be provided is not a handler method.
	 *
	 * @param method the method to provide a mapping for
	 * @param handlerType the handler type, possibly a sub-type of the method's
	 * declaring class
	 * @return the mapping, or {@code null} if the method is not mapped
	 */
	@Nullable
	protected abstract T getMappingForMethod(Method method, Class<?> handlerType);

	/**
	 * Extract and return the URL paths contained in a mapping.
	 */
	protected abstract Set<String> getMappingPathPatterns(T mapping);

	/**
	 * Check if a mapping matches the current request and return a (potentially
	 * new) mapping with conditions relevant to the current request.
	 *
	 * @param mapping the mapping to get a match for
	 * @param request the current HTTP servlet request
	 * @return the match, or {@code null} if the mapping doesn't match
	 */
	@Nullable
	protected abstract T getMatchingMapping(T mapping, HttpServletRequest request);

	/**
	 * Return a comparator for sorting matching mappings.
	 * The returned comparator should sort 'better' matches higher.
	 *
	 * @param request the current request
	 * @return the comparator (never {@code null})
	 */
	protected abstract Comparator<T> getMappingComparator(HttpServletRequest request);


	/**
	 * A registry that maintains all mappings to handler methods, exposing methods
	 * to perform lookups and providing concurrent access.
	 * <p>Package-private for testing purposes.
	 */
	class MappingRegistry {

		/**
		 * Mapping和对应注册器的映射关系
		 */
		private final Map<T, MappingRegistration<T>> registry = new HashMap<>();
		/**
		 * Mapping和对应HandlerMethod的映射关系
		 */
		private final Map<T, HandlerMethod> mappingLookup = new LinkedHashMap<>();
		/**
		 * url与Mapping的一对多映射
		 * <p></p>
		 * 比如 {@code @RequestMapping({"/user/info","/user/information"}}配置了多个uri
		 * 对应一个Mapping对象
		 */
		private final MultiValueMap<String, T> urlLookup = new LinkedMultiValueMap<>();
		/**
		 * Mapping的名称和对应的一组HandlerMethod的映射
		 */
		private final Map<String, List<HandlerMethod>> nameLookup = new ConcurrentHashMap<>();
		/**
		 * HandlerMethod和跨域配置的映射
		 */
		private final Map<HandlerMethod, CorsConfiguration> corsLookup = new ConcurrentHashMap<>();

		private final ReentrantReadWriteLock readWriteLock = new ReentrantReadWriteLock();

		/**
		 * Return all mappings and handler methods. Not thread-safe.
		 *
		 * @see #acquireReadLock()
		 */
		public Map<T, HandlerMethod> getMappings() {
			return this.mappingLookup;
		}

		/**
		 * Return matches for the given URL path. Not thread-safe.
		 *
		 * @see #acquireReadLock()
		 */
		@Nullable
		public List<T> getMappingsByUrl(String urlPath) {
			return this.urlLookup.get(urlPath);
		}

		/**
		 * Return handler methods by mapping name. Thread-safe for concurrent use.
		 */
		public List<HandlerMethod> getHandlerMethodsByMappingName(String mappingName) {
			return this.nameLookup.get(mappingName);
		}

		/**
		 * Return CORS configuration. Thread-safe for concurrent use.
		 */
		public CorsConfiguration getCorsConfiguration(HandlerMethod handlerMethod) {
			HandlerMethod original = handlerMethod.getResolvedFromHandlerMethod();
			return this.corsLookup.get(original != null ? original : handlerMethod);
		}

		/**
		 * 获得读锁
		 * Acquire the read lock when using getMappings and getMappingsByUrl.
		 */
		public void acquireReadLock() {
			this.readWriteLock.readLock().lock();
		}

		/**
		 * 释放读锁
		 * Release the read lock after using getMappings and getMappingsByUrl.
		 */
		public void releaseReadLock() {
			this.readWriteLock.readLock().unlock();
		}

		/**
		 * 注册RequestMapping
		 *
		 * @param mapping 封装了url配置的映射对象，比如{@code @RequestMapping("/user/info/{id}")}
		 * @param handler 分为两种1.{@code @Controller}修饰的类名或者给{@code @Controller}起的别名；2.{@code @Controller}修饰类本身
		 * @param method mapping对应要映射的方法对象，比如{@code @RequestMapping}标注的方法
		 */
		public void register(T mapping, Object handler, Method method) {
			//因为存在多线程对于成员变量的操作，需要加写锁
			this.readWriteLock.writeLock().lock();
			try {
				//创建HandlerMethod
				HandlerMethod handlerMethod = createHandlerMethod(handler, method);
				//确保mapping和HandlerMethod的一一对应
				assertUniqueMethodMapping(handlerMethod, mapping);
				//放入mapping和HandlerMethod对应关系
				this.mappingLookup.put(mapping, handlerMethod);
				//获得mapping对应的url数组，如果路径中存在*或?不会返回
				List<String> directUrls = getDirectUrls(mapping);
				for (String url : directUrls) {
					//将这些url都与当前mapping进行映射
					this.urlLookup.add(url, mapping);
				}

				String name = null;
				//存在命名策略
				if (getNamingStrategy() != null) {
					//根据HandlerMethod和Mapping由命名策略生成Mapping的名称
					name = getNamingStrategy().getName(handlerMethod, mapping);
					//将Mapping名称和HandlerMethod映射放入nameLookup中
					addMappingName(name, handlerMethod);
				}
				//跨域处理
				CorsConfiguration corsConfig = initCorsConfiguration(handler, method, mapping);
				if (corsConfig != null) {
					this.corsLookup.put(handlerMethod, corsConfig);
				}

				//创建一个Mapping、HandlerMethod的注册器，并添加Mapping和这个注册器的映射关系
				this.registry.put(mapping,
						new MappingRegistration<>(mapping, handlerMethod, directUrls, name));
			} finally {
				//释放写锁
				this.readWriteLock.writeLock().unlock();
			}
		}

		/**
		 * 校验mapping对应的HandlerMethod必须是唯一的
		 */
		private void assertUniqueMethodMapping(HandlerMethod newHandlerMethod, T mapping) {
			//获得mapping对应的HandlerMethod
			HandlerMethod handlerMethod = this.mappingLookup.get(mapping);
			//如果新添加的HandlerMethod与老的HandlerMethod不同报错，一个mapping只能映射一个HandlerMethod
			if (handlerMethod != null && !handlerMethod.equals(newHandlerMethod)) {
				throw new IllegalStateException(
						"Ambiguous mapping. Cannot map '" + newHandlerMethod.getBean()
								+ "' method \n" +
								newHandlerMethod + "\nto " + mapping + ": There is already '" +
								handlerMethod.getBean() + "' bean method\n" + handlerMethod
								+ " mapped.");
			}
		}

		private List<String> getDirectUrls(T mapping) {
			List<String> urls = new ArrayList<>(1);
			/**
			 * getMappingPathPatterns会获得mapping配置的路径映射，比如
			 * {@code @RequestMapping("/user/info/{id}")} 中的/user/info/{id}
			 * 就是path pattern，
			 */
			for (String path : getMappingPathPatterns(mapping)) {
				/**
				 * getPathMatcher()获取路径匹配器，可以自己配置，默认是AntPathMatcher。
				 * 该匹配器只会匹配路径中存在*和?的路径
				 */
				if (!getPathMatcher().isPattern(path)) {
					//没有匹配上都放入urls中
					urls.add(path);
				}
			}
			return urls;
		}

		/**
		 * 将Mapping名称和HandlerMethod对应关系放入nameLookup映射中
		 */
		private void addMappingName(String name, HandlerMethod handlerMethod) {
			//Mapping名称存在对应HandlerMethod集合
			List<HandlerMethod> oldList = this.nameLookup.get(name);
			if (oldList == null) {
				oldList = Collections.emptyList();
			}

			//遍历之前的HandlerMethod
			for (HandlerMethod current : oldList) {
				//如果待添加的已经在老HandlerMethod集合中了，直接返回
				if (handlerMethod.equals(current)) {
					return;
				}
			}

			//把新的HandlerMethod加入老集合中
			List<HandlerMethod> newList = new ArrayList<>(oldList.size() + 1);
			newList.addAll(oldList);
			newList.add(handlerMethod);
			this.nameLookup.put(name, newList);
		}

		/**
		 * 移除mapping对应映射
		 */
		public void unregister(T mapping) {
			//获得写锁
			this.readWriteLock.writeLock().lock();
			try {
				//移除mapping对应MappingRegistration
				MappingRegistration<T> definition = this.registry.remove(mapping);
				//没有注册器下面就不用处理了
				if (definition == null) {
					return;
				}

				//移除mapping对应HandlerMethod
				this.mappingLookup.remove(definition.getMapping());
				//遍历mapping对应的url
				for (String url : definition.getDirectUrls()) {
					//获取url对应的所有Mapping
					List<T> list = this.urlLookup.get(url);
					if (list != null) {
						//移除特定Mapping
						list.remove(definition.getMapping());
						//url没有对应Mapping了，将整个映射移除
						if (list.isEmpty()) {
							this.urlLookup.remove(url);
						}
					}
				}
				//从nameLookup中移除Mapping名称对应的映射
				removeMappingName(definition);
				//移除mapping对应HandlerMethod于跨域的映射
				this.corsLookup.remove(definition.getHandlerMethod());
			} finally {
				//释放写锁
				this.readWriteLock.writeLock().unlock();
			}
		}

		private void removeMappingName(MappingRegistration<T> definition) {
			//mapping名称
			String name = definition.getMappingName();
			//没有名字直接返回
			if (name == null) {
				return;
			}
			//HandlerMethod
			HandlerMethod handlerMethod = definition.getHandlerMethod();
			//mapping名称对应的一组HandlerMethod
			List<HandlerMethod> oldList = this.nameLookup.get(name);
			//不存在直接返回
			if (oldList == null) {
				return;
			}
			//就一个HandlerMethod，直接移除返回
			if (oldList.size() <= 1) {
				this.nameLookup.remove(name);
				return;
			}
			List<HandlerMethod> newList = new ArrayList<>(oldList.size() - 1);
			//遍历所有HandlerMethod找到和Mapping一一对应的那个HandlerMethod，删除
			for (HandlerMethod current : oldList) {
				if (!current.equals(handlerMethod)) {
					newList.add(current);
				}
			}
			//将删除之后的handlerMethod集合再放回去
			this.nameLookup.put(name, newList);
		}
	}


	private static class MappingRegistration<T> {

		//Mapping对象
		private final T mapping;
		//Mapping对应HandlerMethod
		private final HandlerMethod handlerMethod;
		//Mapping对应的url列表
		private final List<String> directUrls;

		@Nullable
		//Mapping对应的唯一名称
		private final String mappingName;

		public MappingRegistration(T mapping, HandlerMethod handlerMethod,
				@Nullable List<String> directUrls, @Nullable String mappingName) {

			Assert.notNull(mapping, "Mapping must not be null");
			Assert.notNull(handlerMethod, "HandlerMethod must not be null");
			this.mapping = mapping;
			this.handlerMethod = handlerMethod;
			this.directUrls = (directUrls != null ? directUrls : Collections.emptyList());
			this.mappingName = mappingName;
		}

		public T getMapping() {
			return this.mapping;
		}

		public HandlerMethod getHandlerMethod() {
			return this.handlerMethod;
		}

		public List<String> getDirectUrls() {
			return this.directUrls;
		}

		@Nullable
		public String getMappingName() {
			return this.mappingName;
		}
	}


	/**
	 * 包含与Mapping对象和与之匹配的HandlerMethod对象的匹配对象
	 * A thin wrapper around a matched HandlerMethod and its mapping, for the purpose of
	 * comparing the best match with a comparator in the context of the current request.
	 */
	private class Match {

		private final T mapping;

		private final HandlerMethod handlerMethod;

		public Match(T mapping, HandlerMethod handlerMethod) {
			this.mapping = mapping;
			this.handlerMethod = handlerMethod;
		}

		@Override
		public String toString() {
			return this.mapping.toString();
		}
	}


	private class MatchComparator implements Comparator<Match> {

		private final Comparator<T> comparator;

		public MatchComparator(Comparator<T> comparator) {
			this.comparator = comparator;
		}

		@Override
		public int compare(Match match1, Match match2) {
			return this.comparator.compare(match1.mapping, match2.mapping);
		}
	}


	private static class EmptyHandler {

		@SuppressWarnings("unused")
		public void handle() {
			throw new UnsupportedOperationException("Not implemented");
		}
	}

}
