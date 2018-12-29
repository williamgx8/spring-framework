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

package org.springframework.web.method.annotation;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.servlet.ServletException;

import org.springframework.beans.ConversionNotSupportedException;
import org.springframework.beans.TypeMismatchException;
import org.springframework.beans.factory.config.BeanExpressionContext;
import org.springframework.beans.factory.config.BeanExpressionResolver;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.core.MethodParameter;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.ValueConstants;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.RequestScope;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * 根据包含名称的参数值（请求参数、header参数、路径参数等）解析请求方法对应的参数值抽象类，其中最常用的两个实现是
 * 基于{@code @RequestParam}的RequestParamMethodArgumentResolver参数解析，以及{@code @PathVariable}的
 * PathVariableMethodArgumentResolver参数解析
 * <p></p>
 * Abstract base class for resolving method arguments from a named value.
 * Request parameters, request headers, and path variables are examples of named
 * values. Each may have a name, a required flag, and a default value.
 *
 * <p>Subclasses define how to do the following:
 * <ul>
 * <li>Obtain named value information for a method parameter
 * <li>Resolve names into argument values
 * <li>Handle missing argument values when argument values are required
 * <li>Optionally handle a resolved value
 * </ul>
 *
 * <p>A default value string can contain ${...} placeholders and Spring Expression
 * Language #{...} expressions. For this to work a
 * {@link ConfigurableBeanFactory} must be supplied to the class constructor.
 *
 * <p>A {@link WebDataBinder} is created to apply type conversion to the resolved
 * argument value if it doesn't match the method parameter type.
 *
 * @author Arjen Poutsma
 * @author Rossen Stoyanchev
 * @author Juergen Hoeller
 * @since 3.1
 */
public abstract class AbstractNamedValueMethodArgumentResolver implements HandlerMethodArgumentResolver {

	@Nullable
	private final ConfigurableBeanFactory configurableBeanFactory;

	@Nullable
	private final BeanExpressionContext expressionContext;
	//MethodParameter和NameValueInfo的缓存映射
	private final Map<MethodParameter, NamedValueInfo> namedValueInfoCache = new ConcurrentHashMap<>(256);


	public AbstractNamedValueMethodArgumentResolver() {
		this.configurableBeanFactory = null;
		this.expressionContext = null;
	}

	/**
	 * Create a new {@link AbstractNamedValueMethodArgumentResolver} instance.
	 * @param beanFactory a bean factory to use for resolving ${...} placeholder
	 * and #{...} SpEL expressions in default values, or {@code null} if default
	 * values are not expected to contain expressions
	 */
	public AbstractNamedValueMethodArgumentResolver(@Nullable ConfigurableBeanFactory beanFactory) {
		this.configurableBeanFactory = beanFactory;
		this.expressionContext =
				(beanFactory != null ? new BeanExpressionContext(beanFactory, new RequestScope()) : null);
	}


	@Override
	@Nullable
	public final Object resolveArgument(MethodParameter parameter, @Nullable ModelAndViewContainer mavContainer,
			NativeWebRequest webRequest, @Nullable WebDataBinderFactory binderFactory) throws Exception {
		//获取NamedValueInfo
		NamedValueInfo namedValueInfo = getNamedValueInfo(parameter);
		//如果参数是以Optional包装的，需要得到Optional包装的真实对象或者计算出包装的深度
		MethodParameter nestedParameter = parameter.nestedIfOptional();

		//如果名称中包含占位符和表达式，解析出对应值，否则返回原本的参数名
		Object resolvedName = resolveStringValue(namedValueInfo.name);
		//不存在报错
		if (resolvedName == null) {
			throw new IllegalArgumentException(
					"Specified name must not resolve to null: [" + namedValueInfo.name + "]");
		}
		//调用子类进行参数值的解析，比如@RequestParam对应RequestParamMethodArgumentResolver等
		Object arg = resolveName(resolvedName.toString(), nestedParameter, webRequest);
		//未解析出参数值
		if (arg == null) {
			//如果存在配置好的默认值
			if (namedValueInfo.defaultValue != null) {
				//解析默认值，因为默认值也可能存在占位符和表达式
				arg = resolveStringValue(namedValueInfo.defaultValue);
			}
			//不能存在默认值，看看该参数值是否必要，并且不能是Optional，因为Optional就是不必要
			else if (namedValueInfo.required && !nestedParameter.isOptional()) {
				//如果必要的参数值没有，直接报错
				handleMissingValue(namedValueInfo.name, nestedParameter, webRequest);
			}
			//处理基本类型的null值
			arg = handleNullValue(namedValueInfo.name, arg, nestedParameter.getNestedParameterType());
		}
		//参数值为空字符串，并且设置了默认值
		else if ("".equals(arg) && namedValueInfo.defaultValue != null) {
			//解析配置的默认值，并赋值给参数
			arg = resolveStringValue(namedValueInfo.defaultValue);
		}

		//如果存在配置的@InitBinder对应的转换器
		if (binderFactory != null) {
			//获取与当前request和参数值对应的binder
			WebDataBinder binder = binderFactory.createBinder(webRequest, null, namedValueInfo.name);
			try {
				//调用在binder注册的转换器进行必要的类型转换
				arg = binder.convertIfNecessary(arg, parameter.getParameterType(), parameter);
			}
			catch (ConversionNotSupportedException ex) {
				throw new MethodArgumentConversionNotSupportedException(arg, ex.getRequiredType(),
						namedValueInfo.name, parameter, ex.getCause());
			}
			catch (TypeMismatchException ex) {
				throw new MethodArgumentTypeMismatchException(arg, ex.getRequiredType(),
						namedValueInfo.name, parameter, ex.getCause());

			}
		}
		//对解析完成的值做进一步处理，PathVariableMethodArgumentResolver做了重写
		handleResolvedValue(arg, namedValueInfo.name, parameter, mavContainer, webRequest);

		return arg;
	}

	/**
	 * 根据MethodParameter中的参数名和参数值创建对应的NameValueInfo，并放入namedValueInfoCache缓存
	 * Obtain the named value for the given method parameter.
	 */
	private NamedValueInfo getNamedValueInfo(MethodParameter parameter) {
		//从缓存中获取
		NamedValueInfo namedValueInfo = this.namedValueInfoCache.get(parameter);
		//不存在
		if (namedValueInfo == null) {
			//调用子类实现创建对应的NameValueInfo
			namedValueInfo = createNamedValueInfo(parameter);
			//对原始的NameValueInfo做进一步处理
			namedValueInfo = updateNamedValueInfo(parameter, namedValueInfo);
			//放入缓存
			this.namedValueInfoCache.put(parameter, namedValueInfo);
		}
		//返回
		return namedValueInfo;
	}

	/**
	 * Create the {@link NamedValueInfo} object for the given method parameter. Implementations typically
	 * retrieve the method annotation by means of {@link MethodParameter#getParameterAnnotation(Class)}.
	 * @param parameter the method parameter
	 * @return the named value information
	 */
	protected abstract NamedValueInfo createNamedValueInfo(MethodParameter parameter);

	/**
	 * 进一步处理原始的NamedValueInfo，生成新的NamedValueInfo
	 * Create a new NamedValueInfo based on the given NamedValueInfo with sanitized values.
	 */
	private NamedValueInfo updateNamedValueInfo(MethodParameter parameter, NamedValueInfo info) {
		String name = info.name;
		//参数名为空
		if (info.name.isEmpty()) {
			//从MethodParameter中得到参数名
			name = parameter.getParameterName();
			//MethodParameter中还没有报错
			if (name == null) {
				throw new IllegalArgumentException(
						"Name for argument type [" + parameter.getNestedParameterType().getName() +
						"] not available, and parameter name information not found in class file either.");
			}
		}
		//设置默认值，原始NamedValueInfo中有就用原始的，没有就是null
		String defaultValue = (ValueConstants.DEFAULT_NONE.equals(info.defaultValue) ? null : info.defaultValue);
		//封装新的返回
		return new NamedValueInfo(name, info.required, defaultValue);
	}

	/**
	 * 解析表达式和占位符对应的值
	 * Resolve the given annotation-specified value,
	 * potentially containing placeholders and expressions.
	 */
	@Nullable
	private Object resolveStringValue(String value) {
		if (this.configurableBeanFactory == null) {
			return value;
		}
		//解析占位符的值，比如在@RequestParam中指定defaultValue为${context}，这个值会从System properties中读取
		String placeholdersResolved = this.configurableBeanFactory.resolveEmbeddedValue(value);
		//表达式解析器，解析的表达式以#开头，比如#{systemProperties.systemHeader}
		BeanExpressionResolver exprResolver = this.configurableBeanFactory.getBeanExpressionResolver();
		//不存在表达式解析器直接返回
		if (exprResolver == null || this.expressionContext == null) {
			return value;
		}
		//到这里所有的${}肯定已经解析完了，剩下#{}这种了，进行解析
		return exprResolver.evaluate(placeholdersResolved, this.expressionContext);
	}

	/**
	 * Resolve the given parameter type and value name into an argument value.
	 * @param name the name of the value being resolved
	 * @param parameter the method parameter to resolve to an argument value
	 * (pre-nested in case of a {@link java.util.Optional} declaration)
	 * @param request the current request
	 * @return the resolved argument (may be {@code null})
	 * @throws Exception in case of errors
	 */
	@Nullable
	protected abstract Object resolveName(String name, MethodParameter parameter, NativeWebRequest request)
			throws Exception;

	/**
	 * Invoked when a named value is required, but {@link #resolveName(String, MethodParameter, NativeWebRequest)}
	 * returned {@code null} and there is no default value. Subclasses typically throw an exception in this case.
	 * @param name the name for the value
	 * @param parameter the method parameter
	 * @param request the current request
	 * @since 4.3
	 */
	protected void handleMissingValue(String name, MethodParameter parameter, NativeWebRequest request)
			throws Exception {

		handleMissingValue(name, parameter);
	}

	/**
	 * Invoked when a named value is required, but {@link #resolveName(String, MethodParameter, NativeWebRequest)}
	 * returned {@code null} and there is no default value. Subclasses typically throw an exception in this case.
	 * @param name the name for the value
	 * @param parameter the method parameter
	 */
	protected void handleMissingValue(String name, MethodParameter parameter) throws ServletException {
		throw new ServletRequestBindingException("Missing argument '" + name +
				"' for method parameter of type " + parameter.getNestedParameterType().getSimpleName());
	}

	/**
	 * 处理基本类型的null值数据
	 * A {@code null} results in a {@code false} value for {@code boolean}s or an exception for other primitives.
	 */
	@Nullable
	private Object handleNullValue(String name, @Nullable Object value, Class<?> paramType) {
		if (value == null) {
			//如果参数为布尔型
			if (Boolean.TYPE.equals(paramType)) {
				//默认值为false
				return Boolean.FALSE;
			}
			//其他基本类型报错
			else if (paramType.isPrimitive()) {
				throw new IllegalStateException("Optional " + paramType.getSimpleName() + " parameter '" + name +
						"' is present but cannot be translated into a null value due to being declared as a " +
						"primitive type. Consider declaring it as object wrapper for the corresponding primitive type.");
			}
		}
		return value;
	}

	/**
	 * Invoked after a value is resolved.
	 * @param arg the resolved argument value
	 * @param name the argument name
	 * @param parameter the argument parameter type
	 * @param mavContainer the {@link ModelAndViewContainer} (may be {@code null})
	 * @param webRequest the current request
	 */
	protected void handleResolvedValue(@Nullable Object arg, String name, MethodParameter parameter,
			@Nullable ModelAndViewContainer mavContainer, NativeWebRequest webRequest) {
	}


	/**
	 * 封装 名称--值 的参数实体
	 * <p></p>
	 * Represents the information about a named value, including name, whether it's required and a default value.
	 */
	protected static class NamedValueInfo {

		private final String name;

		private final boolean required;

		@Nullable
		private final String defaultValue;

		public NamedValueInfo(String name, boolean required, @Nullable String defaultValue) {
			this.name = name;
			this.required = required;
			this.defaultValue = defaultValue;
		}
	}

}
