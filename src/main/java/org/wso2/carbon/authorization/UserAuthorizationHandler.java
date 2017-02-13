/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.authorization;

import org.apache.axiom.soap.SOAPHeader;
import org.apache.axiom.soap.SOAPHeaderBlock;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.log4j.Logger;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.rest.AbstractHandler;

import org.apache.synapse.rest.RESTConstants;
import org.apache.synapse.transport.passthru.util.RelayUtils;
import org.apache.ws.security.WSConstants;
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Document;
import org.wso2.carbon.apimgt.gateway.APIMgtGatewayConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.*;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.dto.VerbInfoDTO;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.apache.axis2.Constants;

import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UserAuthorizationHandler extends AbstractHandler {
	static Logger log = Logger.getLogger(UserAuthorizationHandler.class.getName());

	public boolean handleRequest(MessageContext messageContext) {
		if (log.isDebugEnabled()) {
			log.debug("UserAuthorizationHandler engaged.");
		}
		org.apache.axis2.context.MessageContext axis2MessageContext =
				((Axis2MessageContext) messageContext).getAxis2MessageContext();
		Object headers = axis2MessageContext
				.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
		ConfigurationContext axis2ConfigurationContext =
				axis2MessageContext.getConfigurationContext();

		//Add new header to the headers list
		((TreeMap) axis2MessageContext
				.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS))
				.put("SNI_AUTHENTICATED_USER", "value");

		int tenantId = MultitenantUtils.getTenantId(axis2ConfigurationContext);

		String username = null;
		String password = null;
		try {
			RelayUtils.buildMessage(axis2MessageContext);
			SOAPHeader soapHeader = messageContext.getEnvelope().getHeader();
			List<SOAPHeaderBlock> securitySoapHeaders =
					soapHeader.getHeaderBlocksWithNSURI(WSConstants.WSSE_NS);

			if (securitySoapHeaders != null) { //Handle SOAP request
				DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
				factory.setNamespaceAware(true);
				DocumentBuilder builder = factory.newDocumentBuilder();
				Document doc = builder.parse(new java.io.ByteArrayInputStream(
						securitySoapHeaders.get(0).toString().getBytes()));
				XPath xpath = XPathFactory.newInstance().newXPath();
				xpath.setNamespaceContext(new NamespaceContext() {
					public String getNamespaceURI(String prefix) {
						return prefix.equals("wsse") ? WSConstants.WSSE_NS : null;
					}

					public Iterator<?> getPrefixes(String val) {
						return null;
					}

					public String getPrefix(String uri) {
						return null;
					}
				});
				username = xpath.evaluate("//wsse:Username/text()", doc);
				password = xpath.evaluate("//wsse:Password/text()", doc);

			} else { //Handle REST request
				if (headers != null && headers instanceof Map) {
					Map headersMap = (Map) headers;
					if (headersMap.get("Authorization") == null) {
						headersMap.clear();
						return unauthorizedResponse(axis2MessageContext, headers, messageContext, "401");
					} else {
						String authHeader = (String) headersMap.get("Authorization");
						String credentials[] =
								new String(Base64.decode(authHeader.substring(6).trim()))
										.split(":");
						username = credentials[0];
						password = credentials[1];
					}
				}
			}
			return authenticateUser(axis2MessageContext, messageContext, headers, tenantId, username,
			                        password);
		} catch (Exception e) {
			log.error("Unable to execute the authorization process : ", e);
			return false;
		}
	}

	public boolean authenticateUser(org.apache.axis2.context.MessageContext axis2MessageContext,
	                                MessageContext messageContext, Object headers, int tenantId, String username,
	                                String password) throws UserStoreException {
		boolean isAuthenticated;
		RealmService realmService =
				(RealmService) PrivilegedCarbonContext.getThreadLocalCarbonContext()
				                                      .getOSGiService(RealmService.class, null);
		UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
		if (userRealm != null) {
			UserStoreManager userStoreManager = userRealm.getUserStoreManager();
			isAuthenticated = userStoreManager
					.authenticate(MultitenantUtils.getTenantAwareUsername(username), password);
		} else {
			return unauthorizedResponse(axis2MessageContext, headers, messageContext, "500");
		}
		if (isAuthenticated) {
			authenticateInfo(messageContext, username);
			setAPIParametersToMessageContext(messageContext);
			return true;
		} else {
			return unauthorizedResponse(axis2MessageContext, headers, messageContext, "401");
		}
	}

	private void authenticateInfo(MessageContext messageContext, String userName) {
		String clientIP = null;

		org.apache.axis2.context.MessageContext axis2MessageContext =
				((Axis2MessageContext) messageContext).getAxis2MessageContext();
		TreeMap<String, String> transportHeaderMap = (TreeMap<String, String>) axis2MessageContext
				.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

		if (transportHeaderMap != null) {
			clientIP = transportHeaderMap.get(APIMgtGatewayConstants.X_FORWARDED_FOR);
		}

		//Setting IP of the client
		if (clientIP != null && !clientIP.isEmpty()) {
			if (clientIP.indexOf(",") > 0) {
				clientIP = clientIP.substring(0, clientIP.indexOf(","));
			}
		} else {
			clientIP = (String) axis2MessageContext
					.getProperty(org.apache.axis2.context.MessageContext.REMOTE_ADDR);
		}

		AuthenticationContext authContext = new AuthenticationContext();
		authContext.setAuthenticated(true);
		authContext.setTier(APIConstants.UNAUTHENTICATED_TIER);
		authContext.setStopOnQuotaReach(true);
		authContext.setApiKey(clientIP);
		authContext.setKeyType(APIConstants.API_KEY_TYPE_PRODUCTION);
		authContext.setUsername(userName);
		authContext.setCallerToken(null);
		authContext.setApplicationName(null);
		authContext.setApplicationId(clientIP);
		authContext.setConsumerKey(null);
		APISecurityUtils.setAuthenticationContext(messageContext, authContext, null);
	}

	private void setAPIParametersToMessageContext(MessageContext messageContext) {

		AuthenticationContext authContext =
				APISecurityUtils.getAuthenticationContext(messageContext);
		org.apache.axis2.context.MessageContext axis2MsgContext =
				((Axis2MessageContext) messageContext).getAxis2MessageContext();

		String consumerKey = "";
		String username = "";
		String applicationName = "";
		String applicationId = "";
		if (authContext != null) {
			consumerKey = authContext.getConsumerKey();
			username = authContext.getUsername();
			applicationName = authContext.getApplicationName();
			applicationId = authContext.getApplicationId();
		}

		String context = (String) messageContext.getProperty(RESTConstants.REST_API_CONTEXT);
		String apiVersion = (String) messageContext.getProperty(RESTConstants.SYNAPSE_REST_API);

		String apiPublisher =
				(String) messageContext.getProperty(APIMgtGatewayConstants.API_PUBLISHER);
		//if publisher is null,extract the publisher from the api_version
		if (apiPublisher == null) {
			int ind = apiVersion.indexOf("--");
			apiPublisher = apiVersion.substring(0, ind);
			if (apiPublisher.contains(APIConstants.EMAIL_DOMAIN_SEPARATOR_REPLACEMENT)) {
				apiPublisher = apiPublisher.replace(APIConstants.EMAIL_DOMAIN_SEPARATOR_REPLACEMENT,
				                                    APIConstants.EMAIL_DOMAIN_SEPARATOR);
			}
		}
		int index = apiVersion.indexOf("--");

		if (index != -1) {
			apiVersion = apiVersion.substring(index + 2);
		}

		String api = apiVersion.split(":")[0];
		String version =
				(String) messageContext.getProperty(RESTConstants.SYNAPSE_REST_API_VERSION);
		String resource = extractResource(messageContext);
		String method = (String) (axis2MsgContext.getProperty(Constants.Configuration.HTTP_METHOD));
		String hostName = APIUtil.getHostAddress();

		messageContext.setProperty(APIMgtGatewayConstants.CONSUMER_KEY, consumerKey);
		messageContext.setProperty(APIMgtGatewayConstants.USER_ID, username);
		messageContext.setProperty(APIMgtGatewayConstants.CONTEXT, context);
		messageContext.setProperty(APIMgtGatewayConstants.API_VERSION, apiVersion);
		messageContext.setProperty(APIMgtGatewayConstants.API, api);
		messageContext.setProperty(APIMgtGatewayConstants.VERSION, version);
		messageContext.setProperty(APIMgtGatewayConstants.RESOURCE, resource);
		messageContext.setProperty(APIMgtGatewayConstants.HTTP_METHOD, method);
		messageContext.setProperty(APIMgtGatewayConstants.HOST_NAME, hostName);
		messageContext.setProperty(APIMgtGatewayConstants.API_PUBLISHER, apiPublisher);
		messageContext.setProperty(APIMgtGatewayConstants.APPLICATION_NAME, applicationName);
		messageContext.setProperty(APIMgtGatewayConstants.APPLICATION_ID, applicationId);

		APIKeyValidator validator = new APIKeyValidator(null);
		try {
			VerbInfoDTO verb = validator.findMatchingVerb(messageContext);
			if (verb != null) {
				messageContext.setProperty(APIConstants.VERB_INFO_DTO, verb);
			}
		} catch (ResourceNotFoundException e) {
			log.error("Could not find matching resource for request", e);
		} catch (APISecurityException e) {
			log.error("APISecurityException for request:", e);
		}
	}

	private String extractResource(MessageContext mc) {
		String resource = "/";
		Pattern pattern = Pattern.compile("^/.+?/.+?([/?].+)$");
		Matcher matcher =
				pattern.matcher((String) mc.getProperty(RESTConstants.REST_FULL_REQUEST_PATH));
		if (matcher.find()) {
			resource = matcher.group(1);
		}
		return resource;
	}

	private boolean unauthorizedResponse(
			org.apache.axis2.context.MessageContext axis2MessageContext, Object headers,
			MessageContext messageContext, String status) {
		axis2MessageContext.setProperty("HTTP_SC", status);
		Map headersMap = (Map) headers;
		headersMap.put("WWW-Authenticate", "Basic realm=\"WSO2 AM\"");
		axis2MessageContext.setProperty("NO_ENTITY_BODY", new Boolean("true"));
		messageContext.setProperty("RESPONSE", "true");
		messageContext.setTo(null);
		Axis2Sender.sendBack(messageContext);
		return false;
	}

	public void addProperty(String s, Object o) {
	}

	public Map getProperties() {
		log.info("getProperties");
		return null;
	}

	public boolean handleResponse(MessageContext messageContext) {
		return true;
	}
}
