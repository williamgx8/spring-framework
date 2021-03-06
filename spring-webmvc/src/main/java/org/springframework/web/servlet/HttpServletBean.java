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

package org.springframework.web.servlet;

import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.BeanWrapper;
import org.springframework.beans.BeansException;
import org.springframework.beans.MutablePropertyValues;
import org.springframework.beans.PropertyAccessorFactory;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.PropertyValues;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.env.EnvironmentCapable;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceEditor;
import org.springframework.core.io.ResourceLoader;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.ServletContextResourceLoader;
import org.springframework.web.context.support.StandardServletEnvironment;

/**
 * 主要将ServletConfig设置到this对应的BeanWrapper中，相当于通过他Spring就可以获得ServletConfig对象了
 * Simple extension of {@link javax.servlet.http.HttpServlet} which treats
 * its config parameters ({@code init-param} entries within the
 * {@code servlet} tag in {@code web.xml}) as bean properties.
 *
 * <p>A handy superclass for any type of servlet. Type conversion of config
 * parameters is automatic, with the corresponding setter method getting
 * invoked with the converted value. It is also possible for subclasses to
 * specify required properties. Parameters without matching bean property
 * setter will simply be ignored.
 *
 * <p>This servlet leaves request handling to subclasses, inheriting the default
 * behavior of HttpServlet ({@code doGet}, {@code doPost}, etc).
 *
 * <p>This generic servlet base class has no dependency on the Spring
 * {@link org.springframework.context.ApplicationContext} concept. Simple
 * servlets usually don't load their own context but rather access service
 * beans from the Spring root application context, accessible via the
 * filter's {@link #getServletContext() ServletContext} (see
 * {@link org.springframework.web.context.support.WebApplicationContextUtils}).
 *
 * <p>The {@link FrameworkServlet} class is a more specific servlet base
 * class which loads its own application context. FrameworkServlet serves
 * as direct base class of Spring's full-fledged {@link DispatcherServlet}.
 *
 * @author Rod Johnson
 * @author Juergen Hoeller
 * @see #addRequiredProperty
 * @see #initServletBean
 * @see #doGet
 * @see #doPost
 */
@SuppressWarnings("serial")
public abstract class HttpServletBean extends HttpServlet implements EnvironmentCapable,
		EnvironmentAware {

	/**
	 * Logger available to subclasses.
	 */
	protected final Log logger = LogFactory.getLog(getClass());

	@Nullable
	//环境对象
	private ConfigurableEnvironment environment;
	//保存了ServletConfig中必须配置的一些属性
	private final Set<String> requiredProperties = new HashSet<>(4);

	/**
	 * Subclasses can invoke this method to specify that this property
	 * (which must match a JavaBean property they expose) is mandatory,
	 * and must be supplied as a config parameter. This should be called
	 * from the constructor of a subclass.
	 * <p>This method is only relevant in case of traditional initialization
	 * driven by a ServletConfig instance.
	 *
	 * @param property name of the required property
	 */
	protected final void addRequiredProperty(String property) {
		this.requiredProperties.add(property);
	}

	/**
	 * 该接口由EnvironmentAware提供，spring在启动的时候会获取所有EnvironmentAware的子类，并将Environment塞入
	 * 调用该方法
	 * Set the {@code Environment} that this servlet runs in.
	 * <p>Any environment set here overrides the {@link StandardServletEnvironment}
	 * provided by default.
	 *
	 * @throws IllegalArgumentException if environment is not assignable to
	 * {@code ConfigurableEnvironment}
	 */
	@Override
	public void setEnvironment(Environment environment) {
		//环境变量必须是ConfigurableEnvironment的实例
		Assert.isInstanceOf(ConfigurableEnvironment.class, environment,
				"ConfigurableEnvironment required");
		//设置变量
		this.environment = (ConfigurableEnvironment) environment;
	}

	/**
	 * Return the {@link Environment} associated with this servlet.
	 * <p>If none specified, a default environment will be initialized via
	 * {@link #createEnvironment()}.
	 */
	@Override
	public ConfigurableEnvironment getEnvironment() {
		if (this.environment == null) {
			//没有就创建StandardServletEnvironment
			this.environment = createEnvironment();
		}
		return this.environment;
	}

	/**
	 * Create and return a new {@link StandardServletEnvironment}.
	 * <p>Subclasses may override this in order to configure the environment or
	 * specialize the environment type returned.
	 */
	protected ConfigurableEnvironment createEnvironment() {
		return new StandardServletEnvironment();
	}

	/**
	 * GenericServlet提供的初始化Servlet方法
	 * Map config parameters onto bean properties of this servlet, and
	 * invoke subclass initialization.
	 *
	 * @throws ServletException if bean properties are invalid (or required
	 * properties are missing), or if subclass initialization fails.
	 */
	@Override
	public final void init() throws ServletException {

		// Set bean properties from init parameters.
		//ServletConfig相关属性对象(对应<init-params/>配置的内容)，web容器启动时会调用GenericServlet.init(ServletConfig)
		//首先将config设置成员变量，然后调用抽象模板init()，就是这里的方法，
		//第二个参数作用是必须保证ServletConfig中存在requiredProperties中的属性
		PropertyValues pvs = new ServletConfigPropertyValues(getServletConfig(),
				this.requiredProperties);
		if (!pvs.isEmpty()) {
			try {
				//将当前对象封装成对应的BeanWrapper
				BeanWrapper bw = PropertyAccessorFactory.forBeanPropertyAccess(this);
				ResourceLoader resourceLoader = new ServletContextResourceLoader(
						getServletContext());
				//注册属性编辑器ResourceEditor，当遇到Resource.class类型的属性会使用这个属性编辑器进行解析
				bw.registerCustomEditor(Resource.class,
						new ResourceEditor(resourceLoader, getEnvironment()));
				//空实现，子类可以扩充
				initBeanWrapper(bw);
				//将ServletConfig对应的pvs注入到Spring内部的BeanWrapper中
				bw.setPropertyValues(pvs, true);
			} catch (BeansException ex) {
				if (logger.isErrorEnabled()) {
					logger.error(
							"Failed to set bean properties on servlet '" + getServletName() + "'",
							ex);
				}
				throw ex;
			}
		}

		// Let subclasses do whatever initialization they like.
		//子类实现，默认为FrameworkServlet实现
		initServletBean();
	}

	/**
	 * Initialize the BeanWrapper for this HttpServletBean,
	 * possibly with custom editors.
	 * <p>This default implementation is empty.
	 *
	 * @param bw the BeanWrapper to initialize
	 * @throws BeansException if thrown by BeanWrapper methods
	 * @see org.springframework.beans.BeanWrapper#registerCustomEditor
	 */
	protected void initBeanWrapper(BeanWrapper bw) throws BeansException {
	}

	/**
	 * Subclasses may override this to perform custom initialization.
	 * All bean properties of this servlet will have been set before this
	 * method is invoked.
	 * <p>This default implementation is empty.
	 *
	 * @throws ServletException if subclass initialization fails
	 */
	protected void initServletBean() throws ServletException {
	}

	/**
	 * Overridden method that simply returns {@code null} when no
	 * ServletConfig set yet.
	 *
	 * @see #getServletConfig()
	 */
	@Override
	@Nullable
	public String getServletName() {
		return (getServletConfig() != null ? getServletConfig().getServletName() : null);
	}

	/**
	 * PropertyValues implementation created from ServletConfig init parameters.
	 */
	private static class ServletConfigPropertyValues extends MutablePropertyValues {

		/**
		 * Create new ServletConfigPropertyValues.
		 *
		 * @param config the ServletConfig we'll use to take PropertyValues from
		 * @param requiredProperties set of property names we need, where
		 * we can't accept default values
		 * @throws ServletException if any required properties are missing
		 */
		public ServletConfigPropertyValues(ServletConfig config, Set<String> requiredProperties)
				throws ServletException {

			//因为下面要remove所以搞个副本
			Set<String> missingProps = (!CollectionUtils.isEmpty(requiredProperties) ?
					new HashSet<>(requiredProperties) : null);

			//所有ServletConfig属性
			Enumeration<String> paramNames = config.getInitParameterNames();
			while (paramNames.hasMoreElements()) {
				//遍历每一个名字和值
				String property = paramNames.nextElement();
				Object value = config.getInitParameter(property);
				//加到成员变量propertyValueList中
				addPropertyValue(new PropertyValue(property, value));
				if (missingProps != null) {
					//移除一个
					missingProps.remove(property);
				}
			}

			// Fail if we are still missing properties.
			//最后集合不为空说明存在必要的参数没有，报错
			if (!CollectionUtils.isEmpty(missingProps)) {
				throw new ServletException(
						"Initialization from ServletConfig for servlet '" + config.getServletName()
								+
								"' failed; the following required properties were missing: " +
								StringUtils.collectionToDelimitedString(missingProps, ", "));
			}
		}
	}

}
