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

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Part;

import org.springframework.core.MethodParameter;
import org.springframework.core.ResolvableType;
import org.springframework.lang.Nullable;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartRequest;
import org.springframework.web.multipart.support.MultipartResolutionDelegate;

/**
 * 处理{@code RequestParam}配置对应的参数类型为Map，且{@code @RequestParam}中没有配置对应参数的参数名的情况
 * <p></p>
 * Resolves {@link Map} method arguments annotated with an @{@link RequestParam}
 * where the annotation does not specify a request parameter name.
 *
 * <p>The created {@link Map} contains all request parameter name/value pairs,
 * or all multipart files for a given parameter name if specifically declared
 * with {@link MultipartFile} as the value type. If the method parameter type is
 * {@link MultiValueMap} instead, the created map contains all request parameters
 * and all their values for cases where request parameters have multiple values
 * (or multiple multipart files of the same name).
 *
 * @author Arjen Poutsma
 * @author Rossen Stoyanchev
 * @author Juergen Hoeller
 * @since 3.1
 * @see RequestParamMethodArgumentResolver
 * @see HttpServletRequest#getParameterMap()
 * @see MultipartRequest#getMultiFileMap()
 * @see MultipartRequest#getFileMap()
 */
public class RequestParamMapMethodArgumentResolver implements HandlerMethodArgumentResolver {

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		RequestParam requestParam = parameter.getParameterAnnotation(RequestParam.class);
		//支持@RequestParam对应参数类型为Map，且没有配置参数名的情况
		return (requestParam != null && Map.class.isAssignableFrom(parameter.getParameterType()) &&
				!StringUtils.hasText(requestParam.name()));
	}

	@Override
	public Object resolveArgument(MethodParameter parameter, @Nullable ModelAndViewContainer mavContainer,
			NativeWebRequest webRequest, @Nullable WebDataBinderFactory binderFactory) throws Exception {

		//参数被解析后的类型，ResolvableType是对Type类型的增强封装，可以更加方便的获取类的各种属性
		ResolvableType resolvableType = ResolvableType.forMethodParameter(parameter);

		//参数为MultiValueMap类型
		if (MultiValueMap.class.isAssignableFrom(parameter.getParameterType())) {
			// MultiValueMap
			//获取key对应的泛型类型
			Class<?> valueType = resolvableType.as(MultiValueMap.class).getGeneric(1).resolve();
			//key为MultipartFile
			if (valueType == MultipartFile.class) {
				//解析请求为MultipartRequest对象
				MultipartRequest multipartRequest = MultipartResolutionDelegate.resolveMultipartRequest(webRequest);
				return (multipartRequest != null ? multipartRequest.getMultiFileMap() : new LinkedMultiValueMap<>(0));
			}
			//key为Part类型
			else if (valueType == Part.class) {
				HttpServletRequest servletRequest = webRequest.getNativeRequest(HttpServletRequest.class);
				//是multipart请求
				if (servletRequest != null && MultipartResolutionDelegate.isMultipartRequest(servletRequest)) {
					//获得每个部分
					Collection<Part> parts = servletRequest.getParts();
					LinkedMultiValueMap<String, Part> result = new LinkedMultiValueMap<>(parts.size());
					//放入result返回
					for (Part part : parts) {
						result.add(part.getName(), part);
					}
					return result;
				}
				return new LinkedMultiValueMap<>(0);
			}
			else {
				//key为其他类型
				//获取参数Map
				Map<String, String[]> parameterMap = webRequest.getParameterMap();
				MultiValueMap<String, String> result = new LinkedMultiValueMap<>(parameterMap.size());
				//分拆key-value放入result返回
				parameterMap.forEach((key, values) -> {
					for (String value : values) {
						result.add(key, value);
					}
				});
				return result;
			}
		}

		else {
			// Regular Map
			//参数是普通的Map类型
			//获得Map第一个参数类型
			Class<?> valueType = resolvableType.asMap().getGeneric(1).resolve();
			//下面的处理和上面基本一致
			if (valueType == MultipartFile.class) {
				MultipartRequest multipartRequest = MultipartResolutionDelegate.resolveMultipartRequest(webRequest);
				return (multipartRequest != null ? multipartRequest.getFileMap() : new LinkedHashMap<>(0));
			}
			else if (valueType == Part.class) {
				HttpServletRequest servletRequest = webRequest.getNativeRequest(HttpServletRequest.class);
				if (servletRequest != null && MultipartResolutionDelegate.isMultipartRequest(servletRequest)) {
					Collection<Part> parts = servletRequest.getParts();
					LinkedHashMap<String, Part> result = new LinkedHashMap<>(parts.size());
					for (Part part : parts) {
						if (!result.containsKey(part.getName())) {
							result.put(part.getName(), part);
						}
					}
					return result;
				}
				return new LinkedHashMap<>(0);
			}
			else {
				Map<String, String[]> parameterMap = webRequest.getParameterMap();
				Map<String, String> result = new LinkedHashMap<>(parameterMap.size());
				parameterMap.forEach((key, values) -> {
					if (values.length > 0) {
						result.put(key, values[0]);
					}
				});
				return result;
			}
		}
	}

}
