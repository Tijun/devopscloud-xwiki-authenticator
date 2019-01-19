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
package com.h3c.devops.xwiki.authentication.internal;

import com.xpn.xwiki.XWikiContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Access to CAS configurations.
 * 
 * @version $Id$
 */
public final class XWikiDevopsNgConfig
{

    /**
     * Mapping fields separator.
     */
    public static final String DEFAULT_SEPARATOR = ",";

    /**
     * CAS properties names prefix in xwiki.cfg.
     */
    public static final String XWIKI_AUTHENTICATION_DEVOPS = "xwiki.authentication.devops.";

    /**
     * CAS properties names prefix in XWikiPreferences.
     */
    public static final String PREF_DEVOPS_PREFIX = "devops_";

    /**
     * Mapping fields separator.
     */
    public static final String USERMAPPING_SEP = DEFAULT_SEPARATOR;

    /**
     * Character user to link XWiki field name and CAS field name in user mappings property.
     */
    public static final String USERMAPPING_XWIKI_DEVOPS_LINK = "=";

    public static final String PROTOCOL_CAS20 = "CAS20";

    public static final String PROTOCOL_SAML11 = "SAML11";

    /**
     * Logging tool.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(XWikiDevopsNgConfig.class);

    /**
     * Unique instance of {@link XWikiDevopsNgConfig}.
     */
    private static XWikiDevopsNgConfig instance;

    /**
     * Protected constructor. Use {@link #getInstance()}.
     */
    private XWikiDevopsNgConfig()
    {
    }

    /**
     * @return unique instance of {@link XWikiDevopsNgConfig}.
     */
    public static XWikiDevopsNgConfig getInstance()
    {
        if (instance == null) {
            instance = new XWikiDevopsNgConfig();
        }

        return instance;
    }

    /**
     * First try to retrieve value from XWiki Preferences and then from xwiki.cfg Syntax cas_*name* (for XWiki
     * Preferences) will be changed to cas.*name* for xwiki.cfg.
     * 
     * @param prefName the name of the property in XWikiPreferences.
     * @param cfgName the name of the property in xwiki.cfg.
     * @param def default value.
     * @param context the XWiki context.
     * @return the value of the property.
     */
    public String getDEVOPSParam(String prefName, String cfgName, String def, XWikiContext context)
    {
        String param = null;

        try {
            param = context.getWiki().getXWikiPreference(prefName, context);
        } catch (Exception e) {
            LOGGER.error("Failed to get preferences", e);
        }

        if (param == null || "".equals(param)) {
            try {
                param = context.getWiki().Param(cfgName);
            } catch (Exception e) {
                // ignore
            }
        }

        if (param == null) {
            param = def;
        }

        return param;
    }

    /**
     * First try to retrieve value from XWiki Preferences and then from xwiki.cfg Syntax cas_*name* (for XWiki
     * Preferences) will be changed to cas.*name* for xwiki.cfg.
     * 
     * @param name the name of the property in XWikiPreferences.
     * @param def default value.
     * @param context the XWiki context.
     * @return the value of the property.
     */
    public String getDEVOPSParam(String name, String def, XWikiContext context)
    {
        return getDEVOPSParam(name, name.replace(PREF_DEVOPS_PREFIX, XWIKI_AUTHENTICATION_DEVOPS), def, context);
    }

    /**
     * First try to retrieve value from XWiki Preferences and then from xwiki.cfg Syntax cas_*name* (for XWiki
     * Preferences) will be changed to cas.*name* for xwiki.cfg.
     * 
     * @param name the name of the property in XWikiPreferences.
     * @param def default value.
     * @param context the XWiki context.
     * @return the value of the property.
     */
    public long getCASParamAsLong(String name, long def, XWikiContext context)
    {
        String paramStr =
            getDEVOPSParam(name, name.replace(PREF_DEVOPS_PREFIX, XWIKI_AUTHENTICATION_DEVOPS), String.valueOf(def), context);

        long value;

        try {
            value = Long.valueOf(paramStr);
        } catch (Exception e) {
            value = def;
        }

        return value;
    }

    public String getCASProtocol(XWikiContext context)
    {
        return getDEVOPSParam("cas_protocol", PROTOCOL_CAS20, context);
    }

    public boolean isCAS20Protocol(XWikiContext context)
    {
        return PROTOCOL_CAS20.equalsIgnoreCase(getCASProtocol(context));
    }

    public boolean isSAML11Protocol(XWikiContext context)
    {
        return PROTOCOL_SAML11.equalsIgnoreCase(getCASProtocol(context));
    }

    /**
     * Get mapping between XWiki groups names and CAS groups names.
     * 
     * @param context the XWiki context.
     * @return the mapping between XWiki users and CAS users. The key is the XWiki group, and the value is the list of
     *         mapped LDAP groups.
     */
    public Map<String, Set<String>> getGroupMappings(XWikiContext context)
    {
        Map<String, Set<String>> groupMappings = new HashMap<String, Set<String>>();

        String param = getDEVOPSParam("cas_group_mapping", "", context);

        if (param.trim().length() > 0) {
            char[] buffer = param.trim().toCharArray();
            boolean escaped = false;
            StringBuilder mapping = new StringBuilder(param.length());
            for (int i = 0; i < buffer.length; ++i) {
                char c = buffer[i];

                if (escaped) {
                    mapping.append(c);
                    escaped = false;
                } else {
                    if (c == '\\') {
                        escaped = true;
                    } else if (c == '|') {
                        addGroupMapping(mapping.toString(), groupMappings);
                        mapping.setLength(0);
                    } else {
                        mapping.append(c);
                    }
                }
            }

            if (mapping.length() > 0) {
                addGroupMapping(mapping.toString(), groupMappings);
            }
        }

        return groupMappings;
    }

    /**
     * @param mapping the mapping to parse
     * @param groupMappings the map to add parsed group mapping to
     */
    private void addGroupMapping(String mapping, Map<String, Set<String>> groupMappings)
    {
        int splitIndex = mapping.indexOf('=');

        if (splitIndex < 1) {
            LOGGER.error("Error parsing cas_group_mapping attribute [{}]", mapping);
        } else {
            String xwikigroup = mapping.substring(0, splitIndex);
            String casgroup = mapping.substring(splitIndex + 1);

            Set<String> casGroups = groupMappings.get(xwikigroup);

            if (casGroups == null) {
                casGroups = new HashSet<String>();
                groupMappings.put(xwikigroup, casGroups);
            }

            casGroups.add(casgroup);

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Groupmapping found [{}] [{}]", xwikigroup, casGroups);
            }
        }
    }

    /**
     * Get mapping between XWiki users attributes and CAS users attributes.
     * 
     * @param context the XWiki context.
     * @return the mapping between XWiki groups and CAS groups.
     */
    public Map<String, String> getUserMappings(XWikiContext context)
    {
        Map<String, String> userMappings = new HashMap<String, String>();

        String casFieldMapping = getDEVOPSParam("devops_fields_mapping", null, context);

        if (casFieldMapping != null && casFieldMapping.length() > 0) {
            String[] fields = casFieldMapping.split(USERMAPPING_SEP);

            for (int j = 0; j < fields.length; j++) {
                String[] field = fields[j].split(USERMAPPING_XWIKI_DEVOPS_LINK);
                if (2 == field.length) {
                    String xwikiattr = field[0].replace(" ", "");
                    String casattr = field[1].replace(" ", "");

                    userMappings.put(casattr, xwikiattr);

                } else {
                    LOGGER.error("Error parsing cas_fields_mapping attribute in xwiki.cfg: " + fields[j]);
                }
            }
        }

        return userMappings;
    }

}
