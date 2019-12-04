/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package com.h3c.devops.xwiki.authentication;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import com.h3c.devops.xwiki.authentication.internal.UserUtils;
import com.h3c.devops.xwiki.authentication.internal.XWikiDevopsNgConfig;
import com.xpn.xwiki.XWikiConfig;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.ecs.html.S;
import org.securityfilter.filter.SecurityRequestWrapper;
import org.securityfilter.realm.SimplePrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.model.reference.DocumentReference;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import com.xpn.xwiki.web.XWikiRequest;

/**
 * Authentication based on Jasig CAS server. It creates XWiki users if they have never logged in before and synchronizes
 * membership to XWiki groups based on membership to CAS group field mapping.
 * <p>
 * Some parameters can be used to customized its behavior in xwiki.cfg:
 * <ul>
 * <li>xwiki.authentication.cas.server: CAS server url (i.e. https://localhost:8443/cas)</li>
 * <li>xwiki.authentication.cas.protocol: used protocol CAS20 or SAML11</li>
 * <li>xwiki.authentication.cas.access_denied_page: user not authorized page (i.e.
 * /bin/view/XWiki/XWikiCASAccessDenied). If not set a HTTP status 401 is returned.</li>
 * <li>xwiki.authentication.cas.create_user: 0 or 1 if create XWiki user after log in</li>
 * <li>xwiki.authentication.cas.update_user: 0 or 1 if update user attributes after every log in</li>
 * <li>xwiki.authentication.cas.fields_mapping: mapping between XWiki user profile values and CAS attributes. Example
 * (xwiki-attribute=cas-attribute,...): <code>last_name=lastName,first_name=firstName,email=email</code></li>
 * <li>xwiki.authentication.cas.group_field: CAS attribute name which contains group membership</li>
 * <li>xwiki.authentication.cas.group_mapping: Maps XWiki groups to CAS groups, separator is "|".
 * XWiki.XWikiAdminGroup=cn=AdminRole,ou=groups,o=domain,c=com| XWiki.CASUsers=ou=groups,o=domain,c=com</li>
 * </ul>
 *
 * @version $Id$
 */
public class XWikiDevopsAuthenticator extends XWikiAuthServiceImpl
{

    /** LogFactory <code>LOGGER</code>. */
    private static final Logger LOGGER = LoggerFactory.getLogger(XWikiDevopsAuthenticator.class);

    /**
     * The XWiki space where users are stored.
     */
    private static final String XWIKI_USER_SPACE = "XWiki";

    /**
     * Request wrapper auth method
     */
    private static final String AUTH_METHOD = "DEVOPS";

    /**
     * {@inheritDoc}
     *
     * @see com.xpn.xwiki.user.impl.xwiki.AppServerTrustedAuthServiceImpl#checkAuth(com.xpn.xwiki.XWikiContext)
     */
    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        LOGGER.info("start check auth");

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("devops authentication started");
        }

        SecurityRequestWrapper wrappedRequest =
                new SecurityRequestWrapper(context.getRequest().getHttpServletRequest(), null, null, AUTH_METHOD);
        // 不做login限制

      if ("logout".equals(context.getAction()) && wrappedRequest.getUserPrincipal() != null) {
            // TODO redirect to the devops logout page

            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("User " + wrappedRequest.getUserPrincipal().getName() + " has been logged-out");
            }
            wrappedRequest.setUserPrincipal(null);

             XWikiDevopsNgConfig config = XWikiDevopsNgConfig.getInstance();

             String server = config.getDEVOPSParam("devops_server", "", context);
             String logoutUrl = server + config.getDEVOPSParam("devops_logout","/logout",context);

             try {
             context.getResponse().sendRedirect(context.getResponse().encodeRedirectURL(logoutUrl));
             } catch (IOException e) {
             throw new XWikiException(XWikiException.MODULE_XWIKI_USER,
             XWikiException.ERROR_XWIKI_USER_INIT,
             "Can't redirect to the CAS logout page", e);
             }
            return null;

        }
        LOGGER.info("do login");
        doLogin(wrappedRequest,context);

        if (wrappedRequest.getUserPrincipal() == null) {
            return null;
        }
        return new XWikiUser(wrappedRequest.getUserPrincipal().getName());
    }
    private XWikiUser doLogin(SecurityRequestWrapper wrappedRequest,XWikiContext context) throws XWikiException {
        String token = getTokenFromCookie(context.getRequest());
        XWikiDevopsNgConfig config = XWikiDevopsNgConfig.getInstance();
        if (token == null) {
            // redirect to the devops NG login page
            try {

                String devopsServer = config.getDEVOPSParam("devops_server", "", context);
                String devopsLoginPath = config.getDEVOPSParam("devops_login", "", context);
                String devopsLoginPage = devopsServer + devopsLoginPath;
                String serviceUrl = URLEncoder.encode(createServiceUrl(context), "UTF-8");
                LOGGER.info("devops login url {}",devopsLoginPage);
                LOGGER.info("callback service url {}",serviceUrl);
                context.getResponse().sendRedirect(
                        context.getResponse().encodeRedirectURL(devopsLoginPage + "?callback=" + serviceUrl));
            } catch (IOException e) {
                throw new XWikiException(XWikiException.MODULE_XWIKI_USER, XWikiException.ERROR_XWIKI_USER_INIT,
                        "Can't redirect to the CAS login page", e);
            }
            return null;

        } else {
            // authenticate using devops token

            Principal principal = authenticate(token, context);

            if (principal != null) {
                // login successful
                if (LOGGER.isInfoEnabled()) {
                    LOGGER.info("User " + principal.getName() + " has been logged-in");
                }

                // invalidate old session if the user was already
                // authenticated,
                // and they logged in as a different user
                if (wrappedRequest.getUserPrincipal() != null
                        && !principal.getName().equals(wrappedRequest.getRemoteUser())) {
                    wrappedRequest.getSession().invalidate();
                }
            } else {
                String failedPage = config.getDEVOPSParam("devops_access_denied_page", null, context);
                try {
                    if (failedPage != null) {
                        context.getResponse().sendRedirect(
                                context.getResponse().encodeRedirectURL(
                                        context.getRequest().getContextPath() + failedPage));
                    } else {
                        context.getResponse().sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    }
                } catch (IOException e) {
                    throw new XWikiException(XWikiException.MODULE_XWIKI_USER,
                            XWikiException.ERROR_XWIKI_USER_INIT, "Can't authenticate user", e);

                }
            }
            wrappedRequest.setUserPrincipal(principal);
        }
        return null;
    }
    private String getTokenFromCookie(XWikiRequest request){
        Cookie tokenCookie = request.getCookie("devopstoken");
        if (null == tokenCookie || tokenCookie.getValue() == null || "".equals(tokenCookie.getValue())){
            LOGGER.error("get token fail");
            return null;
        }
        return tokenCookie.getValue();
    }
    /**
     * Validate CAS ticket. If success return a principal
     *
     * @param token CAS ticket to validate
     * @param context
     * @return principal of the authenticated user
     * @throws XWikiException
     */
    public Principal authenticate(String token, XWikiContext context) throws XWikiException
    {
        Principal principal = null;

        XWikiDevopsNgConfig config = XWikiDevopsNgConfig.getInstance();

        String devopsServer = config.getDEVOPSParam("devops_server", "", context);
        String devopsLoginUri = config.getDEVOPSParam("devops_login", "", context);
        String devopsAuthInfoUrl = devopsServer + config.getDEVOPSParam("devops_info","",context);

        LOGGER.info("devopsServer {}",devopsServer);
        LOGGER.info("devopsLoginUri {}",devopsLoginUri);
        LOGGER.info("devopsAuthInfoUrl {}",devopsAuthInfoUrl);

            // using token cookie to get auth info from devops
            // service url creation
            String serviceUrl = createServiceUrl(context);
            LOGGER.info("service url {}", serviceUrl);
            // get user info by cookie token
            LOGGER.info("user token is {}",token);
            JSONObject devopsUserInfo = getDevopsUserInfo(devopsAuthInfoUrl, token);
            if (devopsUserInfo == null) {
                // todo error login need redirect to devops login
            }
            // get valid wiki username
        String validXWikiUserName = getDevopsUserAttrValue("username", devopsUserInfo, context);
        // Switch to main wiki to force users to be global users
            context.setDatabase(context.getMainXWiki());
            // user profile
            XWikiDocument userProfile =
                    context.getWiki().getDocument(
                            new DocumentReference(context.getDatabase(), XWIKI_USER_SPACE, validXWikiUserName), context);
            LOGGER.debug("userProfile.get name {}",userProfile.getName());
            LOGGER.debug("userprofie user is new " ,userProfile.isNew());
            // create XWiki principal
            principal = new SimplePrincipal(validXWikiUserName);

            // update or create user
            UserUtils.syncUser(userProfile, devopsUserInfo, context);

        return principal;
    }
    private String getDevopsUserAttrValue(String xwikiUserKey,JSONObject devopsUserAttr,XWikiContext context){
        XWikiDevopsNgConfig instance = XWikiDevopsNgConfig.getInstance();
        Map<String, String> userMappings = instance.getUserMappings(context);
        LOGGER.info("usermappings {}",userMappings);
        userMappings.get(xwikiUserKey);
        return devopsUserAttr.getString(userMappings.get(xwikiUserKey));
    }
    /**
     * Create a devops service url
     *
     * @param context
     * @return
     */
    private String createServiceUrl(XWikiContext context)
    {
        XWikiRequest request = context.getRequest();
        StringBuilder sb = new StringBuilder();
        String wikiHome = context.getWiki().Param("xwiki.home");
        if (wikiHome != null) {
            sb.insert(0, request.getRequestURI());
            sb.deleteCharAt(0);
            sb.insert(0, wikiHome);
        } else {
            sb.insert(0, request.getRequestURL());
        }
        return sb.toString();
    }

    private JSONObject getDevopsUserInfo(String userInfoUrl,String token){
        try {
            HttpClient httpClient = new HttpClient();
            GetMethod getMethod = new GetMethod(userInfoUrl);
            getMethod.addRequestHeader("Cookie","devopstoken=" + token);
            httpClient.executeMethod(getMethod);
            String info = getMethod.getResponseBodyAsString();
            LOGGER.info("devops info {}",info);
            return JSONObject.fromObject(info);
        } catch (IOException e) {
            LOGGER.error("get devops user info fail");
            e.printStackTrace();
        }
        return null;
    }

}
