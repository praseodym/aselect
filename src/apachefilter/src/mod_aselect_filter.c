/*
 * Copyright (c) Stichting SURF. All rights reserved.
 * 
 * A-Select is a trademark registered by SURFnet bv.
 * 
 * This program is distributed under the A-Select license.
 * See the included LICENSE file for details.
 * 
 * If you did not receive a copy of the LICENSE 
 * please contact SURFnet bv. (http://www.surfnet.nl)
 *
 */
// Marked Parts:
// Author: Bauke Hiemstra - www.anoigo.nl

// Bauke 20081108:
// - boolean "aselect_filter_secure_url" to activate URL escape sequence removal
//   default is 1.

// Bauke 20080928:
// - added configurable Logout Bar
// - aselect_filter_trace() calls all replaced by TRACE()

/* 
 * $Id: mod_aselect_filter.c,v 1.10 2006/03/01 08:56:39 remco Exp $
 * 
 * Changelog:
 * $Log: mod_aselect_filter.c,v $
 * Revision 1.10  2006/03/01 08:56:39  remco
 * Added option "url=..." in aselect_filter_add_secure_app, which forces the A-Select Server and filter to redirect to a fixed url after a succesful authentication.
 *
 * Revision 1.9  2005/09/13 14:15:31  remco
 * Fixed small bugs found during system test:
 * - verify_ticket uri is now sent according to API
 * - if rule upload failes filter does not start
 *
 * Revision 1.8  2005/09/12 13:50:49  remco
 * Added authorization support (untested)
 *
 * Revision 1.7  2005/05/23 15:40:42  leon
 * html logout button changed in logout bar template
 *
 * Revision 1.5  2005/05/11 08:20:50  remco
 * Fixed bug with option "remote-organization"
 *
 * Revision 1.4  2005/05/04 13:20:02  remco
 * - Added "remote_organization" config directive
 * - Changed directive "extra" to "extra_parameters"
 *
 * Revision 1.3  2005/05/04 08:55:00  remco
 * - Added application config directive "extra="
 * - Filter now logs if incoming message from Agent is too large
 *
 * Revision 1.2  2005/05/02 09:21:15  remco
 * - Changed parsing of application options
 * - Added 3 new application options: uid, language, and country
 * - Changed internal application storage
 * - Fixed handling of errors: some errors incorrectly resulted in re-authentication. Error response is now the same as in the ISAPI filter.
 *
 * Revision 1.1  2005/04/13 09:44:29  remco
 * RC1 of integrated apache 1.3 & 2.0 filter
 *
 */

#include "asf_common.h"

// -----------------------------------------------------
// Exports
// -----------------------------------------------------
#ifdef APACHE_13_ASELECT_FILTER
module MODULE_VAR_EXPORT    aselect_filter_module;
#else
module AP_MODULE_DECLARE_DATA aselect_filter_module;
#endif


//static handler_rec      aselect_filter_handlers[];
static const command_rec    aselect_filter_cmds[];


// -----------------------------------------------------
// Functions 
// -----------------------------------------------------

int aselect_filter_upload_all_rules(PASELECT_FILTER_CONFIG pConfig, server_rec *pServer, pool *pPool);
int             aselect_filter_upload_authz_rules(PASELECT_FILTER_CONFIG pConfig, server_rec *pServer, pool *pPool, PASELECT_APPLICATION pApp);
char *          aselect_filter_verify_ticket(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcTicket, char *pcUID,
		char *pcOrganization, char *pcAttributes, char *language);
char *          aselect_filter_kill_ticket(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcTicket );
char *          aselect_filter_auth_user(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcAppUrl );
char *          aselect_filter_verify_credentials(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcRID, char *pcCredentials );
static int      aselect_filter_handler(request_rec *pRequest );
static void *   aselect_filter_create_config(pool *pPool, server_rec *pServer );
static int      aselect_filter_verify_config(PASELECT_FILTER_CONFIG pConfig );
static const char * aselect_filter_set_agent_address(cmd_parms *parms, void *mconfig, const char *arg );
static const char * aselect_filter_set_agent_port(cmd_parms *parms, void *mconfig, const char *arg );
static const char * aselect_filter_add_secure_app(cmd_parms *parms, void *mconfig, const char *arg1, const char *arg2, const char *arg3);
static const char * aselect_filter_add_authz_rule(cmd_parms *parms, void *mconfig, const char *arg1, const char *arg2, const char *arg3);
static const char * aselect_filter_set_html_error_template(cmd_parms *parms, void *mconfig, const char *arg );
static const char * aselect_filter_set_html_logout_template(cmd_parms *parms, void *mconfig, const char *arg );
static const char * aselect_filter_set_redirection_mode(cmd_parms *parms, void *mconfig, const char *arg );
static const char * aselect_filter_set_use_aselect_bar(cmd_parms *parms, void *mconfig, const char *arg );
static const char *aselect_filter_secure_url(cmd_parms *parms, void *mconfig, const char *arg );
static const char *aselect_filter_pass_attributes(cmd_parms *parms, void *mconfig, const char *arg );
static const char *aselect_filter_add_attribute(cmd_parms *parms, void *mconfig, const char *arg );

static char * aselect_filter_attributes(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcTicket, char *pcUid, char *pcOrganization);
static int passAttributesInUrl(int iError, char *pcAttributes, pool *pPool, request_rec *pRequest,
	    PASELECT_FILTER_CONFIG pConfig, char *pcTicketIn, char *pcUIDIn, char *pcOrganizationIn, char *pcRequestLanguage, table *headers_in);

//
// Called once during the module initialization phase.
// can be used to setup the filter configuration 
//

#ifdef APACHE_13_ASELECT_FILTER
void
aselect_filter_init(server_rec *pServer, pool *pPool)
#else
int
aselect_filter_init(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *pPool, server_rec *pServer)
#endif
{
    int i;
    PASELECT_APPLICATION pApp;
    char pcMessage[2048];
    PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG) 
        ap_get_module_config(pServer->module_config, &aselect_filter_module);

    TRACE1("aselect_filter_init: %x", pServer);
    if (pConfig)
    {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, pServer,
                "ASELECT_FILTER:: initializing");

        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, pServer,
            ap_psprintf(pPool, "ASELECT_FILTER:: A-Select Agent running on: %s:%d", 
                    pConfig->pcASAIP, pConfig->iASAPort));

        if (pConfig->bUseASelectBar)
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, pServer,
                "ASELECT_FILTER:: configured to use the a-select bar");

        if (pConfig->iRedirectMode == ASELECT_FILTER_REDIRECT_TO_APP)
            ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, pServer,
                "ASELECT_FILTER:: configured to redirect to application entry point" );
        else if (pConfig->iRedirectMode == ASELECT_FILTER_REDIRECT_FULL)
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, pServer,
                "ASELECT_FILTER:: configured to redirect to user entry point");

        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, pServer,
            "ASELECT_FILTER:: configured to use the a-select bar");

	if (!aselect_filter_upload_all_rules(pConfig, pServer, pPool))
#ifdef OLD
        for (i=0; i<pConfig->iAppCount; i++)
        {
            pApp = &pConfig->pApplications[i];
            ap_snprintf(pcMessage, sizeof(pcMessage),
                "ASELECT_FILTER:: added %s at %s %s%s",
                pApp->pcAppId,
                pApp->pcLocation,
                pApp->bEnabled ? "" : "(disabled)",
                pApp->bForcedLogon ? "(forced logon)" : "");
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 
                pServer, pcMessage);
            if (aselect_filter_upload_authz_rules(pConfig, pServer, pPool, pApp))
            {
                ap_snprintf(pcMessage, sizeof(pcMessage), 
                    "ASELECT_FILTER:: registered %d authZ rules for %s",
                    pApp->iRuleCount, pApp->pcAppId);
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 
                    pServer, pcMessage);
            }
            else
#endif
#ifdef APACHE_20_ASELECT_FILTER
                return -1;
#else
                pConfig->bConfigError = 1;
#endif
//      }
    }
    TRACE("aselect_filter_init: done");
#ifdef APACHE_20_ASELECT_FILTER
    return 0;
#endif
}

//
// Bauke: needed this stuff to be able to send the rules again
//
int aselect_filter_upload_all_rules(PASELECT_FILTER_CONFIG pConfig, server_rec *pServer, pool *pPool)
{
    int i;
    PASELECT_APPLICATION pApp;
    char pcMessage[2048];

    for (i=0; i<pConfig->iAppCount; i++)
    {
	pApp = &pConfig->pApplications[i];
	ap_snprintf(pcMessage, sizeof(pcMessage),
	    "ASELECT_FILTER:: added %s at %s %s%s",
	    pApp->pcAppId,
	    pApp->pcLocation,
	    pApp->bEnabled ? "" : "(disabled)",
	    pApp->bForcedLogon ? "(forced logon)" : "");
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, pServer, pcMessage);
	if (aselect_filter_upload_authz_rules(pConfig, pServer, pPool, pApp))
	{
	    ap_snprintf(pcMessage, sizeof(pcMessage), 
		"ASELECT_FILTER:: registered %d authZ rules for %s",
		pApp->iRuleCount, pApp->pcAppId);
	    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, pServer, pcMessage);
	}
	else
	    return 0; // not ok
    }
    return 1; // ok
}

// Upload authorization rule for a single application
int
aselect_filter_upload_authz_rules(PASELECT_FILTER_CONFIG pConfig, 
    server_rec *pServer, pool *pPool, PASELECT_APPLICATION pApp)
{
    int i, length;
    char *pRequest;
    char *pAppId;
    char pRuleId[16];
    char *pcResponse;
    int iRet;
    
    if (pApp->iRuleCount == 0) return 1;
    
    // Calculate size of request
    pAppId = aselect_filter_url_encode(pPool, pApp->pcAppId);
    length = 64 + strlen(pAppId);
    for (i=0; i<pApp->iRuleCount; i++)
    {
        length += 32 + strlen(pApp->pTargets[i]) + 
            strlen(pApp->pConditions[i]);
    }
    
    // Create request
    pRequest = (char *)ap_palloc(pPool, length);
    if (pRequest)
    {
        strcpy(pRequest, "request=set_authorization_rules&app_id=");
        strcat(pRequest, pAppId);
        for (i=0; i<pApp->iRuleCount; i++)
        {
            ap_snprintf(pRuleId, sizeof(pRuleId), "r%d", i);
            strcat(pRequest, "&rules%5B%5D=");
            strcat(pRequest, pRuleId);
            strcat(pRequest, "%3B");
            strcat(pRequest, pApp->pTargets[i]);
            strcat(pRequest, "%3B");
            strcat(pRequest, pApp->pConditions[i]);
        }
        strcat(pRequest, "\r\n");
        
        //TRACE1("aselect_filter_upload_authz_rules: sending: %s", pRequest);
        pcResponse = aselect_filter_send_request(pServer, pPool, pConfig->pcASAIP, pConfig->iASAPort, pRequest, strlen(pRequest));
        if (pcResponse == NULL) {
            // Could not send request, error already logged
            return 0;
        }
        //TRACE1("aselect_filter_upload_authz_rules: response: %s", pcResponse);
        iRet = aselect_filter_get_error(pPool, pcResponse);
        if (iRet != 0) {
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, pServer, 
                ap_psprintf(pPool, "ASELECT_FILTER:: Agent returned "
                    "error %s while uploading authorization rules", 
                    pcResponse));
            return 0;
        }
    }
    else {
        TRACE("aselect_filter_upload_authz_rules: Out of memory");
        return 0;
    }
    return 1;
}

//
// Request validation of a ticket
//
char *
aselect_filter_verify_ticket(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig,
	char *pcTicket, char *pcUID, char *pcOrganization, char *pcAttributes, char *language)
{
    char *          pcSendMessage;
    int             ccSendMessage;
    char *          pcResponse;
    AP_SHA1_CTX     ctxSHA1;
    char            cSHA1[SHA_DIGESTSIZE]; // 20
    char            pcSHA1[64];  // 2* SHA_DIGESTSIZE
    char            *pcURI;
    char langBuf[40];
    
    TRACE1("aselect_filter_verify_ticket: pcAttributes=%s", (pcAttributes)?pcAttributes:"NULL");

    // Create the message
    // Bauke: added
    *pcSHA1 = 0;
    if (pcAttributes && *pcAttributes)
    {
        ap_SHA1Init(&ctxSHA1);
        ap_SHA1Update(&ctxSHA1, pcAttributes, strlen(pcAttributes));
        ap_SHA1Final(cSHA1, &ctxSHA1);
        aselect_filter_bytes_to_hex(cSHA1, sizeof(cSHA1), pcSHA1);
    }

    pcURI = pRequest->uri + strlen(pConfig->pCurrentApp->pcLocation);
    pcURI = aselect_filter_url_encode(pPool, pcURI);
    
    langBuf[0] = '\0';
    if (language)
	sprintf(langBuf, "&language=%s", language);
    if (*pcSHA1)
	pcSendMessage = ap_psprintf(pPool, 
	    "request=verify_ticket&ticket=%s&app_id=%s&uid=%s&organization=%s&attributes_hash=%s&request_uri=%s&ip=%s%s\r\n", 
	    pcTicket, pConfig->pCurrentApp->pcAppId, pcUID, pcOrganization, 
	    pcSHA1, pcURI, pRequest->connection->remote_ip, langBuf);
    else // No attribute hash available, so don't ask for an attribute check
	pcSendMessage = ap_psprintf(pPool, 
	    "request=verify_ticket&ticket=%s&app_id=%s&uid=%s&organization=%s&request_uri=%s&ip=%s%s\r\n", 
	    pcTicket, pConfig->pCurrentApp->pcAppId, pcUID, pcOrganization, 
	    pcURI, pRequest->connection->remote_ip, langBuf);

    ccSendMessage = strlen(pcSendMessage);

    //TRACE2("request(%d): %s", ccSendMessage, pcSendMessage);
    pcResponse = aselect_filter_send_request(pRequest->server, pPool, pConfig->pcASAIP, pConfig->iASAPort,
			pcSendMessage, ccSendMessage);
    return pcResponse;
}

//
// Kills the ticket
//
char *aselect_filter_kill_ticket(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcTicket)
{
    char            *pcSendMessage;
    int             ccSendMessage;
    char            *pcResponse;

    //
    // Create the message
    //
    TRACE("aselect_filter_kill_ticket");
    pcSendMessage = ap_psprintf(pPool, "request=kill_ticket&ticket=%s&app_id=%s\r\n", 
	    aselect_filter_url_encode(pPool, pcTicket), aselect_filter_url_encode(pPool, pConfig->pCurrentApp->pcAppId));
    ccSendMessage = strlen(pcSendMessage);

    //TRACE2("request(%d): %s", ccSendMessage, pcSendMessage);
    pcResponse = aselect_filter_send_request(pRequest->server, pPool, pConfig->pcASAIP, pConfig->iASAPort,
		    pcSendMessage, ccSendMessage);
    return pcResponse;
}

//
// Request an authentication of a user
//
char *aselect_filter_auth_user(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcAppUrl)
{
    char    *pcSendMessage;
    int     ccSendMessage;
    char    *pcResponse;

    TRACE("aselect_filter_auth_user");

    //
    // Create the message
    //
    pcSendMessage = ap_psprintf(pPool, "request=authenticate&app_url=%s&app_id=%s&forced_logon=%s%s%s%s%s%s%s\r\n", 
        aselect_filter_url_encode(pPool, pcAppUrl), 
        aselect_filter_url_encode(pPool, pConfig->pCurrentApp->pcAppId),
        pConfig->pCurrentApp->bForcedLogon ? "true" : "false",
        pConfig->pCurrentApp->pcUid,
        pConfig->pCurrentApp->pcAuthsp,
        pConfig->pCurrentApp->pcCountry,
        pConfig->pCurrentApp->pcLanguage,
        pConfig->pCurrentApp->pcRemoteOrg,
        pConfig->pCurrentApp->pcExtra);
    ccSendMessage = strlen(pcSendMessage);

    //TRACE2("request(%d): %s", ccSendMessage, pcSendMessage);

    if ((pcResponse = aselect_filter_send_request(pRequest->server, pPool, pConfig->pcASAIP, pConfig->iASAPort, pcSendMessage, ccSendMessage)))
    {
        //TRACE1("response message: %s", pcResponse);
    }
    else { // socket error occured, take appropiate action
        pcResponse = NULL;
    }
    return pcResponse;
}

// Bauke 20081201: added to support Saml token in a header
//
static char *getRequestedAttributes(pool *pPool, PASELECT_FILTER_CONFIG pConfig)
{
    char *p, *q, *paramNames = NULL;
    char ldapName[90];
    int i, len;

    for (i = 0; i < pConfig->iAttrCount; i++) {
	p = pConfig->pAttrFilter[i];
	TRACE2("getRequestedAttributes:: %d: %s", i, p);
	ldapName[0] = '\0';
	q = strchr(p, ',');
	if (q) {  // digidName
	    p = q+1;
	    q = strchr(p, ',');
	    if (q) {  // ldapName
		len = (q-p < sizeof(ldapName))? q-p: sizeof(ldapName)-1;
		strncpy(ldapName, p, len);
		ldapName[len] = '\0';
	    }
	    // Also continue when attrName is empty
	}
	if (ldapName[0] == '\0')
	    continue;

	// Decent ldapName present, if it's a constant, skip it
	if (ldapName[0] == '\'' && ldapName[strlen(ldapName)-1] == '\'')
	    continue;

	// Add ldapName
	if (paramNames)
	    paramNames = ap_psprintf(pPool, "%s,%s", paramNames, ldapName);
	else
	    paramNames = ap_psprintf(pPool, "%s", ldapName);
    }
    return paramNames;
}

//
// Verify the credentials
// sends the RID and the credentials to the Aselect Agent for verification
// Bauke 20081201: added saml_attributes
//
char *aselect_filter_verify_credentials(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcRID, char *pcCredentials)
{
    char    *pcSendMessage;
    int     ccSendMessage;
    char    *pcResponse;
    char *attrNames = NULL;

    //
    // Create the message
    //
    TRACE("aselect_filter_verify_credentials");
    if (strchr(pConfig->pcPassAttributes,'t')!=0) {
	// Need token later on, pass the attribute names we need
	attrNames = getRequestedAttributes(pPool, pConfig);
    }
    pcSendMessage = ap_psprintf(pPool, "request=verify_credentials&rid=%s&aselect_credentials=%s%s%s\r\n", 
	    aselect_filter_url_encode(pPool, pcRID), aselect_filter_url_encode(pPool, pcCredentials),
	    (attrNames)? "&saml_attributes=": "", (attrNames)? attrNames: "");
    ccSendMessage = strlen(pcSendMessage);

    //TRACE2("request(%d): %s", ccSendMessage, pcSendMessage);
    pcResponse = aselect_filter_send_request(pRequest->server, pPool, pConfig->pcASAIP,
                            pConfig->iASAPort, pcSendMessage, ccSendMessage);

    return pcResponse;
}

//
// Bauke: Added:
// Retrieve Attribute values from the Agent
//
char *aselect_filter_attributes(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcTicket, char *pcUid, char *pcOrganization)
{
    char    *pcSendMessage;
    int     ccSendMessage;
    char    *pcResponse;

    TRACE("aselect_filter_attributes");
    //
    // Create the message
    //
    pcSendMessage = ap_psprintf(pPool, "request=attributes&ticket=%s&uid=%s&organization=%s\r\n", 
		aselect_filter_url_encode(pPool, pcTicket), aselect_filter_url_encode(pPool, pcUid),
		aselect_filter_url_encode(pPool, pcOrganization));
    ccSendMessage = strlen(pcSendMessage);

    //TRACE2("request(%d): %s", ccSendMessage, pcSendMessage);
    if ((pcResponse = aselect_filter_send_request(pRequest->server, pPool, pConfig->pcASAIP, pConfig->iASAPort, pcSendMessage, ccSendMessage)))
    {
        //TRACE1("response message: %s", pcResponse);
    }
    else { // could not send request to A-Select Agent
        pcResponse = NULL;
    }
    return pcResponse;
}


static int
aselect_filter_verify_config(PASELECT_FILTER_CONFIG pConfig)
{
    if (pConfig->bConfigError)
        return ASELECT_FILTER_ERROR_CONFIG;
    if (pConfig->pcASAIP)
    {
	if (strlen(pConfig->pcASAIP) <= 0)
            return ASELECT_FILTER_ERROR_CONFIG;
    }
    else
        return ASELECT_FILTER_ERROR_CONFIG;

    if (pConfig->iASAPort == 0)
        return ASELECT_FILTER_ERROR_CONFIG;

    if (pConfig->iAppCount == 0)
        return ASELECT_FILTER_ERROR_CONFIG;

    if (!pConfig->pcErrorTemplate || strlen(pConfig->pcErrorTemplate) <= 0)
	return ASELECT_FILTER_ERROR_CONFIG;

    if (!pConfig->pcLogoutTemplate || strlen(pConfig->pcLogoutTemplate) <= 0)
	return ASELECT_FILTER_ERROR_CONFIG;
    
    return ASELECT_FILTER_ERROR_OK;
}


//
// Main handler, will handle cookie checking and redirection
//
static int
aselect_filter_handler(request_rec *pRequest)
{
    int             iRet = FORBIDDEN;
    int             iError = ASELECT_FILTER_ERROR_OK;
    int             iAction = ASELECT_FILTER_ACTION_ACCESS_DENIED;
    table           *headers_in = pRequest->headers_in;
    table           *headers_out = pRequest->headers_out;
    PASELECT_FILTER_CONFIG  pConfig;
    char            *pcTicketIn;
    char            *pcTicketOut = NULL;
    char            *pcUIDIn;
    char            *pcUIDOut = NULL;
    char            *pcOrganizationIn;
    char            *pcOrganizationOut = NULL;
    char            *pcAttributesIn;
    char            *pcTicket;
    char            *pcCredentials;
    char            *pcRID;
    char            *pcAppUrl;
    char            *pcCookie;
    char            *pcCookie2;
    char            *pcCookie3;
    char            *pcCookie4;
    char            *pcASUrl;
    char            *pcASelectServer;
    char            *pcResponseVT;
    char            *pcResponseAU;
    char            *pcResponseCred;
    pool            *pPool;
    char            *pcUrl;
    char            *pcRequest;
    char            *pcASelectAppURL;
    char            *pcASelectServerURL;
    char            *pcResponseKill;
    char            *pcTmp;
    char            *pcTmp2;
    char            *pcStrippedParams;
    char            *pcAttributes = NULL;
    int             bFirstParam;
    char * pcRequestLanguage = NULL;

    ap_log_error(APLOG_MARK, APLOG_INFO, pRequest->server, ap_psprintf(pRequest->pool, "XX Url - %s", pRequest->uri));
    TRACE("");
    TRACE("----------------------------------------------------------- aselect_filter_handler");
    TRACE2("GET %s %s", pRequest->uri, pRequest->args);
    TRACE("-----------------------------------------------------------");
    ap_table_do(aselect_filter_print_table, pRequest, headers_in, NULL);

    //
    // Select which pool to use
    //
#ifdef APACHE_13_ASELECT_FILTER
    if ((pPool = ap_make_sub_pool(pRequest->pool)) == NULL)
#else
    if ((apr_pool_create(&pPool, pRequest->pool)) != APR_SUCCESS)
#endif
    {
        // Could not allocate pool
        TRACE("aselect_filter_handler:: could not allocate memory pool");
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pRequest,
             "ASELECT_FILTER:: could allocate memory pool");
        return iRet;
    }

    // 20091114, Bauke: report application language back to the Server
    // TODO: Should look into the POST data as well!
    // Currently callers have to specify the language as an URL parameter
    pcRequestLanguage = aselect_filter_get_param(pPool, pRequest->args, "language=", "&", TRUE);

    //
    // NOTE: the application ticket is a cookie, check if the browser can handle cookies else we run into a loop
    // check cookie, no cookie, validate_user, set cookie, check cookie, no cookie.... and so on
    
    // Read config data
    if (!(pConfig = (PASELECT_FILTER_CONFIG) 
        ap_get_module_config(pRequest->server->module_config, &aselect_filter_module)))
    {
        // Something went wrong, access denied
        TRACE("could not get module config data");
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pRequest,
            "ASELECT_FILTER:: could not retrieve configuration data");

        // Cleanup
        ap_destroy_pool(pPool);
        return iRet;
    }
    else { // Verify configuration
	TRACE1("IP=%s", (pConfig->pcASAIP)? pConfig->pcASAIP: "NULL");
	TRACE1("Port=%d", pConfig->iASAPort);
        if (aselect_filter_verify_config(pConfig) != ASELECT_FILTER_ERROR_OK)
        {
            TRACE("invalid configuration data");
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pRequest,
                "ASELECT_FILTER:: invalid configuration data");
            return iRet;
        }
    }

    //
    // Check if we are in a protected dir
    // this function point the global pConfig->pCurrentApp to the requested app
    //
    if (aselect_filter_verify_directory(pPool, pConfig, pRequest->uri) == ASELECT_FILTER_ERROR_FAILED)
    {
        //
        // not in a protected dir
        // this should not be possible
        // but we let the request through anyway
        //
        TRACE1("\"%s\" is not a protected dir (or is disabled)", pRequest->uri);
        ap_destroy_pool(pPool);   
        return DECLINED;
    }
    else
    {
        TRACE2("\"%s\" is a protected dir, app_id: %s", pRequest->uri, pConfig->pCurrentApp->pcAppId);
    }

    //
    // Retrieve the remote_addr
    //
    if (pRequest->connection->remote_ip) 
    {
        TRACE1("remote_ip: %s", pRequest->connection->remote_ip);
    }

    TRACE3("==== 1. Start iError=%d iAction=%s, iRet=%d", iError, filter_action_text(iAction), iRet);
    TRACE3("     (DECLINED=%d DONE=%d FORBIDDEN=%d)", DECLINED, DONE, FORBIDDEN);
    //
    // Check for application ticket
    //
    if ((pcTicketIn = aselect_filter_get_cookie(pPool, headers_in, "aselectticket=")))
    {
        TRACE1("aselect_filter_handler: found ticket: %s", pcTicketIn);
        
        //
        // Check for user ID
        //
        if ((pcUIDIn = aselect_filter_get_cookie(pPool, headers_in, "aselectuid=")))
        {
            TRACE1("aselect_filter_handler: found uid: %s", pcUIDIn);
            
            //
            // Check for Organization 
            //
            if ((pcOrganizationIn = aselect_filter_get_cookie(pPool, headers_in, "aselectorganization=")))
            {
                TRACE3("aselect_filter_handler: found organization: %s, bSecureUrl=%d PassAttributes=%s",
			pcOrganizationIn, pConfig->bSecureUrl, pConfig->pcPassAttributes);

                //
                // Check attributes
                //
                pcAttributesIn = aselect_filter_get_cookie(pPool, headers_in, "aselectattributes=");
		// Bauke: changed
		// If attributes are not stored in a cookie,
		// the value will not be checked with the A-Select server.
                //if (/*!pConfig->bUseCookie ||*/ (pcAttributesIn) )
		if (1 == 1)
                {
                    TRACE1("aselect_filter_handler: attributes cookie: %s", pcAttributesIn? pcAttributesIn: "NULL");
                    //
                    // Validate ticket
                    //
		    // Bauke: added, always send rules
		    aselect_filter_upload_all_rules(pConfig, pRequest->server, pPool);

                    if ((pcResponseVT = aselect_filter_verify_ticket(pRequest, pPool, pConfig, pcTicketIn, pcUIDIn, pcOrganizationIn, pcAttributesIn, pcRequestLanguage)))
                    {
                        iError = aselect_filter_get_error(pPool, pcResponseVT);
                        if (iError == ASELECT_FILTER_ASAGENT_ERROR_OK) {
                            // User has ticket, ACCESS GRANTED
			    // 20091114, Bauke: Possibly a server language was passed back
			    pcTmp = aselect_filter_get_param(pPool, pcResponseVT, "language=", "&", TRUE);
			    if (pcTmp != NULL) {
				TRACE1("Return language=%s", pcTmp);
			    	pcRequestLanguage = pcTmp;
			    }
                            iAction = ASELECT_FILTER_ACTION_ACCESS_GRANTED;
                            TRACE("aselect_filter_handler: User has ticket: ACCESS_GRANTED");
                        }
                        else {
                            if (iError == ASELECT_SERVER_ERROR_TGT_NOT_VALID ||
                                iError == ASELECT_SERVER_ERROR_TGT_EXPIRED ||
                                iError == ASELECT_SERVER_ERROR_TGT_TOO_LOW ||
                                iError == ASELECT_SERVER_ERROR_UNKNOWN_TGT ||  // Bauke, 20080928 added
                                iError == ASELECT_FILTER_ASAGENT_ERROR_TICKET_INVALID ||
                                iError == ASELECT_FILTER_ASAGENT_ERROR_TICKET_EXPIRED ||
                                iError == ASELECT_FILTER_ASAGENT_ERROR_UNKNOWN_TICKET)
                            {
                                iError = ASELECT_FILTER_ERROR_OK;
                                iAction = ASELECT_FILTER_ACTION_VERIFY_CREDENTIALS;
				TRACE("aselect_filter_handler: Invalid ticket: VERIFY_CREDENTIALS");
                            }
                            else {
                                TRACE1("aselect_filter_verify_ticket FAILED (%d)", iError);
                                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, pRequest,
                                    ap_psprintf(pPool, "ASELECT_FILTER::aselect_filter_verify_ticket FAILED (%d)", iError));
                            }
                        }
                    }
                }
                else { // Ticket verification failed, check if credentials is valid (if credentials is present)
                    iError = ASELECT_FILTER_ASAGENT_ERROR_CORRUPT_ATTRIBUTES;
                }
            }
            else
            {
                //
                // Could not find a inst-id, check if the user has credentials 
                //
                iAction = ASELECT_FILTER_ACTION_VERIFY_CREDENTIALS;
            }
        }
        else
        {
            //
            // Could not find a user-id, check if the user has credentials 
            //
            iAction = ASELECT_FILTER_ACTION_VERIFY_CREDENTIALS;
        }
    }
    else
    {
        //
        // Could not find a application ticket, check if the user has credentials
        //
        iAction = ASELECT_FILTER_ACTION_VERIFY_CREDENTIALS;
    }

    TRACE3("==== 2. Verify iError=%d iAction=%s, iRet=%d", iError, filter_action_text(iAction), iRet);
    if (iAction == ASELECT_FILTER_ACTION_VERIFY_CREDENTIALS)
    {
        TRACE1("Verify Credentials, ARGUMENTS: %s", pRequest->args);

        //
        // Check for user credentials 
        //
        if ((pcCredentials = aselect_filter_get_param(pPool, pRequest->args, "aselect_credentials=", "&", TRUE)))
        {
            TRACE1("aselect_credentials: %s", pcCredentials);

            if ((pcRID = aselect_filter_get_param(pPool, pRequest->args, "rid=", "&", TRUE)))
            {
                //
                // Found credentials, now verify them, if ok it returns a ticket
                //
                if ((pcResponseCred = aselect_filter_verify_credentials(pRequest, pPool, pConfig, pcRID, pcCredentials)))
                {
                    iError = aselect_filter_get_error(pPool, pcResponseCred);
                    if (iError == ASELECT_FILTER_ERROR_INTERNAL)
                        iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;

                    if (iError == ASELECT_FILTER_ASAGENT_ERROR_OK)
                    {
                        //
                        // User credentials are ok, set application ticket and let user through
                        //
			TRACE1("aselect_credentials, response [%s]", pcResponseCred?pcResponseCred:"NULL");
                        if ((pcTicketOut = aselect_filter_get_param(pPool, pcResponseCred, "ticket=", "&", TRUE)) != NULL)
                        {
                            //
                            // Save Uid
                            //
                            if ((pcUIDOut = aselect_filter_get_param(pPool, pcResponseCred, "uid=", "&", TRUE)))
                            {
                                if ((pcOrganizationOut = aselect_filter_get_param(pPool, pcResponseCred, "organization=", "&", TRUE)))
                                {
                                    pcAttributes = aselect_filter_get_param(pPool, pcResponseCred, "attributes=", "&", TRUE);
                                    if (pcAttributes)
                                        pcAttributes = aselect_filter_base64_decode(pPool, pcAttributes);
                                    iAction = ASELECT_FILTER_ACTION_SET_TICKET;
                                }
                                else
                                {
                                    TRACE1("could not find organization in response: %s", pcResponseCred);
                                    iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;
                                }
                            }
                            else
                            {
                                TRACE1("could not find uid in response: %s", pcResponseCred);
                                iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;
                            }
                        }
                        else
                        {
                            //
                            // Could not find ticket in response
                            //
                            TRACE1("could not find ticket in response: %s", pcResponseCred);
                            iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;
                        }
                    }
                    else
                    {
                        TRACE1("aselect_filter_verify_tgt FAILED (%d)", iError);
                        if (iError == ASELECT_SERVER_ERROR_TGT_NOT_VALID ||
                            iError == ASELECT_SERVER_ERROR_TGT_EXPIRED ||
                            iError == ASELECT_SERVER_ERROR_TGT_TOO_LOW ||
			    iError == ASELECT_SERVER_ERROR_UNKNOWN_TGT ||  // Bauke, 20080928 added
                            iError == ASELECT_FILTER_ASAGENT_ERROR_TICKET_INVALID ||
                            iError == ASELECT_FILTER_ASAGENT_ERROR_TICKET_EXPIRED ||
                            iError == ASELECT_FILTER_ASAGENT_ERROR_UNKNOWN_TICKET)
                        {
                            iAction = ASELECT_FILTER_ACTION_AUTH_USER;
                            iError = ASELECT_FILTER_ERROR_OK;
                        }
                    }
                }
                else
                {
                    iError = ASELECT_FILTER_ERROR_AGENT_NO_RESPONSE;
                }
            }
            else
            {
                //
                // Could not find a RID, authenticate user
                //
                iAction = ASELECT_FILTER_ACTION_AUTH_USER;
            }
        }
        else
        {
            //
            // No Credentials present, authenticate user
            //
            iAction = ASELECT_FILTER_ACTION_AUTH_USER;
        }
    }
    TRACE3("==== 3. Action iError=%d iAction=%s, iRet=%d", iError, filter_action_text(iAction), iRet);

    //
    // if we do not have an error then
    // act according to iAction
    //
    if (iError == ASELECT_FILTER_ERROR_OK)
    {
        //
        // Act according to action
        //
        switch(iAction)
        {
            case ASELECT_FILTER_ACTION_ACCESS_GRANTED:

                //
                // User was granted access
                //
                TRACE1("Action: ASELECT_FILTER_ACTION_ACCESS_GRANTED, args=%s", pRequest->args);

                //
                // check for requests such as show_aselect_bar and kill_ticket
                //
                if (pRequest->args)
                {
                    if ((pcRequest = aselect_filter_get_param(pPool, pRequest->args, "request=", "&", TRUE)))
                    {
			TRACE1("pcRequest=%s", pcRequest);
                        if (strstr(pcRequest, "aselect_show_bar") && pConfig->bUseASelectBar)
                        {
                            //
                            // must show the the aselect_bar
                            //
                            if ((pcASelectAppURL = aselect_filter_get_param(pPool, pRequest->args, "aselect_app_url=", "&", TRUE)))
                                iRet = aselect_filter_show_barhtml(pPool, pRequest, pConfig, pcASelectAppURL);
                            else
                                iRet = aselect_filter_show_barhtml(pPool, pRequest, pConfig, pConfig->pCurrentApp->pcLocation);
                        }
                        else if (strstr(pcRequest, "aselect_generate_bar"))
                        {
                            // return the bar html content
			    char *pcLogoutHTML = pConfig->pcLogoutTemplate;

			    TRACE1("aselect_generate_bar, logout loc=%s", pConfig->pCurrentApp->pcLocation);
                            pRequest->content_type = "text/html";
                            ap_send_http_header(pRequest);

			    // Bauke 20080928: added configurable Logout Bar
			    while (pcLogoutHTML && (strstr(pcLogoutHTML, "[action]") != NULL)) {
				pcLogoutHTML = aselect_filter_replace_tag(pPool, "[action]", pConfig->pCurrentApp->pcLocation, pcLogoutHTML);
			    }

			    ap_rprintf(pRequest, "%s\n", (pcLogoutHTML)? pcLogoutHTML: "");
                            // OLD ap_rprintf(pRequest, ASELECT_LOGOUT_BAR, pConfig->pCurrentApp->pcLocation);
                            iRet = DONE;
                        }
                        else if (strstr(pcRequest, "aselect_kill_ticket"))
                        {
                            //
                            // kill the user ticket
                            //
                            if ((pcTicket = aselect_filter_get_cookie(pPool, headers_in, "aselectticket=")))
                            {
                                if ((pcResponseKill = aselect_filter_kill_ticket(pRequest, pPool, pConfig, pcTicket)))
                                {
				    iError = aselect_filter_get_error(pPool, pcResponseKill);

				    if (iError == ASELECT_FILTER_ASAGENT_ERROR_OK)
				    {
					//
					// Successfully killed the ticket, now redirect to the aselect-server
					//
					if ((pcASelectServerURL = aselect_filter_get_cookie(pPool, headers_in, "aselectserverurl=")))
					{
					    pRequest->content_type = "text/html";
					    
					    pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s; secure; HttpOnly", "aselectticket", pConfig->pCurrentApp->pcLocation);
					    ap_table_add(headers_out, "Set-Cookie", pcCookie);
					    TRACE1("Set-Cookie: %s", pcCookie);
					    pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s; secure; HttpOnly", "aselectuid", pConfig->pCurrentApp->pcLocation);
					    ap_table_add(headers_out, "Set-Cookie", pcCookie);
					    TRACE1("Set-Cookie: %s", pcCookie);
					    pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s; secure; HttpOnly", "aselectorganization", pConfig->pCurrentApp->pcLocation);
					    ap_table_add(headers_out, "Set-Cookie", pcCookie);
					    TRACE1("Set-Cookie: %s", pcCookie);
					    pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s; secure; HttpOnly", "aselectserverurl", pConfig->pCurrentApp->pcLocation);
					    ap_table_add(headers_out, "Set-Cookie", pcCookie);
					    TRACE1("Set-Cookie: %s", pcCookie);
					    if (/*pConfig->bUseCookie ||*/ strchr(pConfig->pcPassAttributes,'c')!=0) {  // Bauke: added
						pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s; secure; HttpOnly", "aselectattributes", pConfig->pCurrentApp->pcLocation);
						ap_table_add(headers_out, "Set-Cookie", pcCookie);
						TRACE1("Set-Cookie: %s", pcCookie);
					    }
					    // else: no aselectattributes cookie needed

					    ap_send_http_header(pRequest);
					    ap_rprintf(pRequest, ASELECT_FILTER_CLIENT_REDIRECT, pcASelectServerURL, pcASelectServerURL);

					    iRet = DONE;
                                        }
                                        else
                                        {
                                            iError = ASELECT_FILTER_ERROR_NO_SUCH_COOKIE;
                                            TRACE1("aselect_filter_get_cookie(aselectserverurl) FAILED: %d", iError);
                                            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, pRequest,
                                                ap_psprintf(pPool, "ASELECT_FILTER::aselect_filter_get_cookie(aselectserverurl) FAILED: %d", iError));
                                        }
                                    }
                                    else
                                    {
                                        TRACE1("aselect_filter_kill_ticket FAILED: %d", iError);
                                        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, pRequest,
                                            ap_psprintf(pPool, "ASELECT_FILTER::aselect_filter_kill_ticket FAILED: %d", iError));
                                    }
                                }
                                else
                                {
                                    iError = ASELECT_FILTER_ERROR_INTERNAL;
                                    TRACE1("aselect_filter_kill_ticket FAILED: %d", iError);
                                    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, pRequest,
                                        ap_psprintf(pPool, "ASELECT_FILTER::aselect_filter_kill_ticket FAILED: %d", iError));
                                }
                            }
                            else { // Could not find ticket to kill
                                iError = ASELECT_FILTER_ERROR_NO_SUCH_COOKIE;
                                TRACE1("aselect_filter_get_cookie(aselectticket) FAILED: %d", iError);
                                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, pRequest,
                                    ap_psprintf(pPool, "ASELECT_FILTER::aselect_filter_get_cookie(aselectticket) FAILED: %d", iError));
                            }
                        }
                        else { // Nothing interesting in the request=param, so continue as normal
                            iRet = DECLINED;
                        }
                    }
                    else { // No arguments we are intereste in, so continue as normal
                        iRet = DECLINED;
                    }
                }
                else {
                    iRet = DECLINED;
                }

            break;

            case ASELECT_FILTER_ACTION_AUTH_USER:
            
                //
                // user does not have a valid CREDENTIALS and must be authenticated by the ASelect Server
                // Contact ASelect Agent to find the users ASelect Server
                //      

                TRACE("Action: ASELECT_FILTER_ACTION_AUTH_USER");
                TRACE1("iRedirectMode: %d", pConfig->iRedirectMode);
                if (*pConfig->pCurrentApp->pcRedirectURL)
                {
                    TRACE1("Using fixed app_url: %s", pConfig->pCurrentApp->pcRedirectURL);
                    if (pRequest->args != NULL)
                    {
                      if (strchr(pConfig->pCurrentApp->pcRedirectURL, '?'))
                          pcAppUrl = ap_psprintf(pPool, "%s&%s", pConfig->pCurrentApp->pcRedirectURL,
                              pRequest->args);
                      else
                          pcAppUrl = ap_psprintf(pPool, "%s?%s", pConfig->pCurrentApp->pcRedirectURL,
                              pRequest->args);
                    }
                    else
                      pcAppUrl = pConfig->pCurrentApp->pcRedirectURL;
                }
                else
                {
                  if (pConfig->iRedirectMode == ASELECT_FILTER_REDIRECT_FULL)
                  {
                      if (pRequest->args != NULL)
                      {
                          pcUrl = ap_psprintf(pPool, "%s?%s", pRequest->uri, pRequest->args);
                          pcAppUrl = ap_construct_url(pPool, pcUrl, pRequest);
                      }
                      else
                          pcAppUrl = ap_construct_url(pPool, pRequest->uri, pRequest);
                  }
                  else
                      pcAppUrl = ap_construct_url(pPool, pConfig->pCurrentApp->pcLocation, pRequest);
                }
                
                TRACE1("Redirect for authentication to app_url: %s", pcAppUrl);

                if ((pcResponseAU = aselect_filter_auth_user(pRequest, pPool, pConfig, pcAppUrl)))
                {
                    iError = aselect_filter_get_error(pPool, pcResponseAU);
                }

                if (iError == ASELECT_FILTER_ASAGENT_ERROR_OK)
                {
                    TRACE1("response: %s", pcResponseAU);
                    //
                    // build the redirection URL from the response
                    //
                    if ((pcRID = aselect_filter_get_param(pPool, pcResponseAU, "rid=", "&", TRUE)))
                    {
                        if ((pcASelectServer = aselect_filter_get_param(pPool, pcResponseAU, "a-select-server=", "&", TRUE)))
                        {
                            if ((pcASUrl = aselect_filter_get_param(pPool, pcResponseAU, "as_url=", "&", TRUE)))
                            {
                                iRet = aselect_filter_gen_top_redirect(pPool, pRequest, pcASUrl, pcASelectServer, pcRID);
                            }
                            else {
                                iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;
                            }
                        }
                        else {
                            iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;
                        }
                    }
                    else {
                        iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;
                    }
                }
                else {
                    TRACE1("aselect_filter_auth_user FAILED (%d)", iError);
                    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, pRequest,
                        ap_psprintf(pPool, "ASELECT_FILTER::aselect_filter_auth_user FAILED (%d)", iError));
                }
            
                break;

            case ASELECT_FILTER_ACTION_SET_TICKET:

                //
                // Generate & set A-Select cookies
                //
                TRACE3("Action: ASELECT_FILTER_ACTION_SET_TICKET: %s - %s - %s", pcTicketOut, pcUIDOut, pcOrganizationOut);
		if (/*pConfig->bUseCookie ||*/ strchr(pConfig->pcPassAttributes,'c')!=0) {  // Bauke: added
		    // Pass attributes in a cookie
		    pcCookie4 = ap_psprintf(pPool, "%s=%s; version=1; path=%s; secure; HttpOnly", "aselectattributes", 
			(pcAttributes == NULL) ? "" : pcAttributes, pConfig->pCurrentApp->pcLocation);
		    TRACE1("Set-Cookie: %s", pcCookie4);
		    ap_table_add(headers_out, "Set-Cookie", pcCookie4); 
		}
		if (/*!pConfig->bUseCookie ||*/ strchr(pConfig->pcPassAttributes,'q')!=0 ||
			    strchr(pConfig->pcPassAttributes,'h')!=0 || strchr(pConfig->pcPassAttributes,'t')!=0) {  // Bauke: added
		    // Pass attributes in the html header and/or query string
		    iError = passAttributesInUrl(iError, pcAttributes, pPool, pRequest, pConfig,
				    pcTicketOut, pcUIDOut, pcOrganizationOut, pcRequestLanguage, headers_in);
		}

                pcCookie = ap_psprintf(pPool, "%s=%s; version=1; path=%s; secure; HttpOnly", "aselectticket", 
                    pcTicketOut, pConfig->pCurrentApp->pcLocation);
                TRACE1("Set-Cookie: %s", pcCookie);
                ap_table_add(headers_out, "Set-Cookie", pcCookie); 

                pcCookie2 = ap_psprintf(pPool, "%s=%s; version=1; path=%s; secure; HttpOnly", "aselectuid", 
                    pcUIDOut, pConfig->pCurrentApp->pcLocation);
                TRACE1("Set-Cookie: %s", pcCookie2);
                ap_table_add(headers_out, "Set-Cookie", pcCookie2); 

                pcCookie3 = ap_psprintf(pPool, "%s=%s; version=1; path=%s; secure; HttpOnly", "aselectorganization", 
                    pcOrganizationOut, pConfig->pCurrentApp->pcLocation);
                TRACE1("Set-Cookie: %s", pcCookie3);
                ap_table_add(headers_out, "Set-Cookie", pcCookie3); 

                TRACE2("SecureUrl=%d RequestArgs: '%s'", pConfig->bSecureUrl, pRequest->args);
                pcStrippedParams  = NULL;
                bFirstParam = TRUE;
                pcTmp = strtok(pRequest->args, "?&");
                while (pcTmp != NULL)
                {
		    // Skip these parameters:
                    if ((pcTmp2 = strstr(pcTmp, "aselect_credentials")) == NULL) {
	                if ((pcTmp2 = strstr(pcTmp, "rid")) == NULL) {
     	                    if ((pcTmp2 = strstr(pcTmp, "a-select-server")) == NULL) {
				// The rest will pass
    	                        if (bFirstParam) {
    	                            pcStrippedParams = ap_psprintf(pPool, "?%s", pcTmp);
    	                            bFirstParam = FALSE;
    	                        }
    	                        else
    	                            pcStrippedParams = ap_psprintf(pPool, "%s&%s", pcStrippedParams, pcTmp);
    	                     }
	                 }
                    }
                    pcTmp = strtok(NULL, "?&");
                }

                if (pcStrippedParams != NULL)
                    pRequest->args = pcStrippedParams;
                else
                    pRequest->args = "";
                TRACE1("--> pRequest->args='%s'",pRequest->args);
                                                                         
                iRet = aselect_filter_gen_authcomplete_redirect(
                    pPool, pRequest, pConfig);
                break;

            case ASELECT_FILTER_ACTION_ACCESS_DENIED:
                TRACE("Action: ACCESS_DENIED");

            default:
                // Access is denied or unknown action: ACCESS DENIED
		break;
        }
    }

    if (iError != ASELECT_FILTER_ERROR_OK) {
        if (aselect_filter_gen_error_page(pPool, pRequest, iError, pConfig->pcErrorTemplate) == ASELECT_FILTER_ERROR_OK)
            iRet = DONE;
    }

    // Bauke: added
    if (iError == ASELECT_FILTER_ERROR_OK && iAction == ASELECT_FILTER_ACTION_ACCESS_GRANTED) { /*!pConfig->bUseCookie ||*/
	if (strchr(pConfig->pcPassAttributes,'q')!=0 || strchr(pConfig->pcPassAttributes,'h')!=0 || strchr(pConfig->pcPassAttributes,'t')!=0) {
	    iError = passAttributesInUrl(iError, pcAttributes, pPool, pRequest, pConfig, pcTicketIn, pcUIDIn, pcOrganizationIn, pcRequestLanguage, headers_in);
	}
	//iRet = DONE;
    }

    TRACE3("==== 4. Finish iError=%d iAction=%s, iRet=%d", iError, filter_action_text(iAction), iRet);
    //
    // Cleanup
    //
    ap_destroy_pool(pPool);
    TRACE2("==== 5. Returning %d: %s", iRet, (iRet==DECLINED)? "DECLINED": (iRet==DONE)? "DONE": (iRet==FORBIDDEN)? "FORBIDDEN": "?");

    return iRet;
}

//
// Bauke added: Pass attributes in the query string and/or in the header
//
static int passAttributesInUrl(int iError, char *pcAttributes, pool *pPool, request_rec *pRequest,
	    PASELECT_FILTER_CONFIG pConfig, char *pcTicketIn, char *pcUIDIn, char *pcOrganizationIn, char *pcRequestLanguage, table *headers_in)
{
    TRACE4("==== Attributes iError=%d, TicketIn=%s, UidIn=%s, OrgIn=%s", iError,
		pcTicketIn?pcTicketIn:"NULL", pcUIDIn?pcUIDIn:"NULL", pcOrganizationIn?pcOrganizationIn:"NULL");
    if (pcAttributes == NULL) {
	int i, purge, stop;
	char *pcResponse, *newArgs;

	TRACE("Get Attributes");
	pcResponse = aselect_filter_attributes(pRequest, pPool, pConfig, pcTicketIn, pcUIDIn, pcOrganizationIn);
	if (pcResponse) {
	    TRACE1("Response Attributes [%s]", pcResponse);
	    iError = aselect_filter_get_error(pPool, pcResponse);

	    if (iError == ASELECT_FILTER_ASAGENT_ERROR_OK) {
		newArgs = "";  // Start with no args at all
		pcAttributes = aselect_filter_get_param(pPool, pcResponse, "attributes=", "&", TRUE);
		if (pcAttributes) {
		    pcAttributes = aselect_filter_base64_decode(pPool, pcAttributes);

		    TRACE2("Start: SecureUrl=%d pRequestArgs=%s", pConfig->bSecureUrl, (pRequest->args)? pRequest->args: "NULL");
		    TRACE1("Attributes from Agent: %s", pcAttributes);
		    // Filter out unwanted characters in the URL
		    for (stop=0 ; pConfig->bSecureUrl && !stop && pRequest->args; ) {
			int len = strlen(pRequest->args);
			aselect_filter_url_decode(pRequest->args);
			TRACE1("Loop: %s", (pRequest->args)? pRequest->args: "NULL");
			if (len == strlen(pRequest->args)) {
			    char *p, *q;
			    for (p = q = pRequest->args; *q; ) {
				if (*q == '%' || *q == '\r' || *q == '\n' || *q == '>' || *q == '<')
				    q++;
				else
				    *p++ = *q++;
			    }
			    *p++ = '\0';
			    stop = 1;
			}
		    }
		    TRACE2("End: %s, AttrCount=%d", (pRequest->args)? pRequest->args: "NULL", pConfig->iAttrCount);

		    // Perform attribute filtering!
		    // First handle the special Saml attribute token (if present)
		    if (strchr(pConfig->pcPassAttributes,'t')!=0) {  // Pass Saml token in header
			char *p, *q, hdrName[40];
			int i, len, save;

			p = aselect_filter_get_param(pPool, pcAttributes, "saml_attribute_token=", "&", TRUE/*UrlDecode*/);
			// We have a base64 encoded Saml token, pass it in a custom header
			// Note the minus signs in the header name instead of underscores
			len = strlen(p);
			for (i = 1; p && *p && len > 0; i++) {
			    if (len > ASELECT_FILTER_MAX_HEADER_SIZE) {
				q = p + ASELECT_FILTER_MAX_HEADER_SIZE;
				save = *q;
				*q = '\0';
			    }
			    sprintf(hdrName, "X-saml-attribute-token%d", i);
			    TRACE2("%s: %.100s", hdrName, p);
			    ap_table_set(headers_in, hdrName, p);
			    if (len > ASELECT_FILTER_MAX_HEADER_SIZE) {  // restore
				*q = save;
				p = q;
			    }
			    len -= ASELECT_FILTER_MAX_HEADER_SIZE;
			}
		    }

		    // The config file tells us which attributes to pass on and from which source
		    // If not present in the Ldap attributes, use the DigiD value!
		    for (i = 0; i < pConfig->iAttrCount; i++) {
			char *p, *q, *is;
			char digidName[90], ldapName[90], attrName[90], buf[260];
			int len, constant;

			p = pConfig->pAttrFilter[i];
			TRACE2("aselect_filter_attribute_check:: %d: %s", i, p);

			digidName[0] = ldapName[0] = attrName[0] = '\0';
			q = strchr(p, ',');
			if (q) {  // digidName
			    len = (q-p < sizeof(digidName))? q-p: sizeof(digidName)-1;
			    strncpy(digidName, p, len);
			    digidName[len] = '\0';
			    p = q+1;
			    q = strchr(p, ',');
			    if (q) {  // ldapName
				len = (q-p < sizeof(ldapName))? q-p: sizeof(ldapName)-1;
				strncpy(ldapName, p, len);
				ldapName[len] = '\0';
				p = q+1;
				for (q=p; *q; q++)
				    ;
				//attrName
				len = (q-p < sizeof(attrName))? q-p: sizeof(attrName)-1;
				strncpy(attrName, p, len);
				attrName[len] = '\0';
			    }
			}
			if (attrName[0] == '\0')  // no HTTP header name
			    continue;

			TRACE3("Attr %s,%s,%s", digidName, ldapName, attrName);
			// attrName has a value
			if (strcmp(attrName, "language")==0) {
			    char *p = (pRequest->args)? strstr(pRequest->args, "language="): NULL;
			    if (pcRequestLanguage != NULL) {
				// Server has a language for us, must be passed, don't skip
			    }
			    else if (p != NULL && (p == pRequest->args || *(p-1) == '&' || *(p-1) == ' ')) {
				// No server language, but language in application parameters, it takes precedence
				// over the A-Select attribute, leave application parameter in place
				TRACE1("Request: skip attr language: %s", p);
				continue; 
			    }
			}

			// Pass this attribute, either in the Query string or in the HTTP-header
			p = NULL;
			constant = 0;
			if (ldapName[0] != '\0') {  // try to use Ldap value
			    // Can also be a constant, e.g. 'I am a constant' (no quote escapes possible)
			    if (ldapName[0] == '\'' && ldapName[strlen(ldapName)-1] == '\'') {
				p = ldapName + 1;
				ldapName[strlen(ldapName)-1] = '\0';
				constant = 1;  // Allows a value of '' (empty string)
			    }
			    else {
				sprintf(buf, "%s=", ldapName);
				p = aselect_filter_get_param(pPool, pcAttributes, buf, "&", FALSE);
			    }
			}
			if (!constant && !(p && *p) && digidName[0] != '\0') {  // try to use DigiD value
			    sprintf(buf, "digid_%s=", digidName);
			    p = aselect_filter_get_param(pPool, pcAttributes, buf, "&", FALSE);
			}
			if (strcmp(attrName, "language")==0 && pcRequestLanguage != NULL) {
			    p = pcRequestLanguage; // replace attribute value
			    constant = 0;
			}
			if (p && (*p||constant)) {
			    if (newArgs[0])
				newArgs = ap_psprintf(pPool, "%s&%s=%s", newArgs, attrName, p);
			    else
				newArgs = ap_psprintf(pPool, "%s=%s", attrName, p);

			    if (strcmp(attrName, "AuthHeader") == 0) {
				char *encoded, *decoded;
				decoded = ap_psprintf(pPool, "%s:", p);
				aselect_filter_url_decode(decoded);
				encoded = aselect_filter_base64_encode(pPool, decoded);
				ap_table_set(headers_in, "Authorization", ap_psprintf(pPool, "Basic %s", encoded));
			    }
			    else if (strchr(pConfig->pcPassAttributes,'h')!=0) {
				// Pass in the header
				TRACE2("X-Header - %s: %s", attrName, p);
				ap_log_error(APLOG_MARK, APLOG_INFO, pRequest->server,
					    ap_psprintf(pPool, "X-Header - %s: %s", attrName, p));
				ap_table_set(headers_in, ap_psprintf(pPool, "X-%s", attrName), p);
			    }

			    // A value for 'attrname' was added
			    // Remove the same attribute from the original attributes (if present), can occur more than once
			    for (purge=1; purge; ) {
				purge = 0;
				for (p = pRequest->args; p != NULL; p = q+1) {
				    q = strstr(p, attrName);
				    if (!q)
					break;
				    // Bauke: example args: my_uid=9876&uid2=0000&uid=1234&uid=9876
				    if (q==pRequest->args || *(q-1) == '&' || *(q-1) == ' ') {
					int nextChar = *(q+strlen(attrName));
					if (nextChar == '=' || nextChar  == '&' || nextChar == '\0') {
					    purge = 1;
					    break;  // handle this one
					}
				    }
				}
				if (purge) {  // found, purge attribute from Request args
				    char *r;
				    for (r=q; *r && *r != '&'; r++)
					;
				    if (*r == '&')
					r++;
				    TRACE2("Purge '%.*s'", r-q, q);
				    // r on begin of next attribute
				    for ( ; *r; )
					*q++ = *r++;
				    *q = '\0';
				    if (q > pRequest->args && *(q-1) == '&')  // 't was the last
					*(q-1) = '\0';
				}
			    }
			}
			TRACE3("New arguments [%d]: %s, req=%s", i, newArgs, pRequest->args);
		    }
		}
		else {
		    TRACE("No attributes in response");
		    //pRequest->args = "";
		}
		TRACE1("PassAttributes=%s", pConfig->pcPassAttributes);
		if (strchr(pConfig->pcPassAttributes,'q')!=0) {
		    // Add the new args in front of the original ones
		    if (pRequest->args && pRequest->args[0])
			pRequest->args = ap_psprintf(pPool, "%s&%s", newArgs, pRequest->args);
		    else
			pRequest->args = newArgs;
		    // If we want to do this, do-not encode the = and & signs!!!
		    //pRequest->args = aselect_filter_url_encode(pPool, pRequest->args);
		}
		TRACE2("Args%s modified to [%s]", (strchr(pConfig->pcPassAttributes,'q')!=0)? "": " NOT", pRequest->args);
	    }
	    else iError = ASELECT_FILTER_ERROR_FAILED;
	}
	else iError = ASELECT_FILTER_ERROR_AGENT_NO_RESPONSE;
    }
    return iError;
}

//
// Use to create the per server configuration data
//
static void*
aselect_filter_create_config(pool *pPool, server_rec *pServer)
{
    PASELECT_FILTER_CONFIG  pConfig = NULL;

    TRACE("aselect_filter_create_config");
    if ((pConfig = (PASELECT_FILTER_CONFIG) ap_palloc(pPool, sizeof(ASELECT_FILTER_CONFIG))))
    {
        memset(pConfig, 0, sizeof(ASELECT_FILTER_CONFIG));
    }
    else
    {
	TRACE("aselect_filter_create_config::ERROR:: could not allocate memory for pConfig");
    }

    return pConfig;
}

static const char *
aselect_filter_set_agent_address(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);

    if (pConfig)
    {
        if ((pConfig->pcASAIP = ap_pstrdup(parms->pool, arg)))
        {
            TRACE1("aselect_filter_set_agent_address:: ip: %s", pConfig->pcASAIP);
        }
        else
        {
            return "A-Select ERROR: Internal error when setting A-Select IP";
        }
    }
    else
    {
        return "A-Select ERROR: Internal error when setting A-Select IP";
    }

    return NULL;
}

static const char *
aselect_filter_set_agent_port(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    char                    *pcASAPort;

    if (pConfig)
    {
        if ((pcASAPort = ap_pstrdup(parms->pool, arg)))
        {
            TRACE1("aselect_filter_set_agent_port:: port: %s", pcASAPort);
            pConfig->iASAPort = atoi(pcASAPort);
        }
        else
        {
            return "A-Select ERROR: Internal error when setting A-Select port";
        }
    }
    else
    {
        return "A-Select ERROR: Internal error when setting A-Select port";
    }

    return NULL;
}

static const char *
aselect_filter_add_authz_rule(cmd_parms *parms, void *mconfig, const char *arg1, const char *arg2, const char *arg3)
{
    int i;
    PASELECT_APPLICATION pApp;
    PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG) 
        ap_get_module_config(parms->server->module_config, &aselect_filter_module);

    if (pConfig)
    {
        for (i=0; i<pConfig->iAppCount; i++)
        {
            if (strcmp(pConfig->pApplications[i].pcAppId, arg1) == 0)
                break;
        }
        if (i >= pConfig->iAppCount)
        {
            TRACE1("aselect_filter_add_authz_rule: Unknown app_id \"%s\"", arg1);
            return "A-Select ERROR: Unknown application ID in authorization rule";
        }
        pApp = &pConfig->pApplications[i];
        if (pApp->iRuleCount == ASELECT_FILTER_MAX_RULES_PER_APP)
            return "A-Select ERROR: Maximum amount of authorization rules per application exceeded";
        pApp->pTargets[pApp->iRuleCount] = aselect_filter_url_encode(parms->pool, arg2);
        pApp->pConditions[pApp->iRuleCount] = aselect_filter_url_encode(parms->pool, arg3);
        TRACE3("aselect_filter_add_authz_rule: app=%s, target=%s, added condition \"%s\"",
            arg1, arg2, arg3);
        ++(pApp->iRuleCount);
    }
    else
    {
        return "A-Select ERROR: Internal error: missing configuration object";
    }

    return NULL;
}

static const char *
aselect_filter_add_secure_app(cmd_parms *parms, void *mconfig, const char *arg1, const char *arg2, const char *arg3)
{
    static char *_empty = "";
    const char *pcTok, *pcEnd;
    PASELECT_APPLICATION pApp;
    PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG) 
        ap_get_module_config(parms->server->module_config, &aselect_filter_module);

    if (pConfig)
    {
        if (pConfig->iAppCount < ASELECT_FILTER_MAX_APP)
        {
            pApp = &pConfig->pApplications[pConfig->iAppCount];
            memset(pApp, 0, sizeof(ASELECT_APPLICATION));
            pApp->bEnabled = 1;
            pApp->pcUid = _empty;
            pApp->pcAuthsp = _empty;
            pApp->pcLanguage = _empty;
            pApp->pcCountry = _empty;
            pApp->pcExtra = _empty;
            pApp->pcRemoteOrg = _empty;
            pApp->pcRedirectURL = _empty;
            if ( (pApp->pcLocation = ap_pstrdup(parms->pool, arg1)) &&
                 (pApp->pcAppId = ap_pstrdup(parms->pool, arg2)) )
            {
                if (strcmp(arg3, "none") != 0 &&
                    strcmp(arg3, "default") != 0)
                {
                    pcTok = arg3;
                    while (*pcTok)
                    {
                        TRACE1("Parsing application options token %s", pcTok);
                        if (strncmp(pcTok, "forced-logon", 12) == 0 ||
                            strncmp(pcTok, "forced_logon", 12) == 0)
                        {
                            pcTok += 12;
                            pApp->bForcedLogon = 1;
                        }
                        else
                        if (strncmp(pcTok, "disabled", 8) == 0)
                        {
                            pcTok += 8;
                            pApp->bEnabled = 0;
                        }
                        else
                        if (strncmp(pcTok, "uid=", 4) == 0)
                        {
                            pcTok += 4;
                            if ((pcEnd = strchr(pcTok, ',')))
                                pApp->pcUid = ap_pstrndup(parms->pool, pcTok, pcEnd-pcTok);
                            else
                                pApp->pcUid = ap_pstrdup(parms->pool, pcTok);
                            pcTok += strlen(pApp->pcUid);
                            pApp->pcUid = ap_psprintf(parms->pool, "&uid=%s",
                                aselect_filter_url_encode(parms->pool, pApp->pcUid));
                        }
                        else
			/* Bauke: added to force the AuthSP choice */
                        if (strncmp(pcTok, "authsp=", 7) == 0)
                        {
                            pcTok += 7;
                            if ((pcEnd = strchr(pcTok, ',')))
                                pApp->pcAuthsp = ap_pstrndup(parms->pool, pcTok, pcEnd-pcTok);
                            else
                                pApp->pcAuthsp = ap_pstrdup(parms->pool, pcTok);
                            pcTok += strlen(pApp->pcAuthsp);
                            pApp->pcAuthsp = ap_psprintf(parms->pool, "&authsp=%s",
                                aselect_filter_url_encode(parms->pool, pApp->pcAuthsp));
                        }
                        else
                        if (strncmp(pcTok, "language=", 9) == 0)
                        {
                            pcTok += 9;
                            if ((pcEnd = strchr(pcTok, ',')))
                                pApp->pcLanguage = ap_pstrndup(parms->pool, pcTok, pcEnd-pcTok);
                            else
                                pApp->pcLanguage = ap_pstrdup(parms->pool, pcTok);
                            pcTok += strlen(pApp->pcLanguage);
                            pApp->pcLanguage = ap_psprintf(parms->pool, "&language=%s",
                                aselect_filter_url_encode(parms->pool, pApp->pcLanguage));
                        }
                        else
                        if (strncmp(pcTok, "country=", 8) == 0)
                        {
                            pcTok += 8;
                            if ((pcEnd = strchr(pcTok, ',')))
                                pApp->pcCountry = ap_pstrndup(parms->pool, pcTok, pcEnd-pcTok);
                            else
                                pApp->pcCountry = ap_pstrdup(parms->pool, pcTok);
                            pcTok += strlen(pApp->pcCountry);
                            pApp->pcCountry = ap_psprintf(parms->pool, "&country=%s",
                                aselect_filter_url_encode(parms->pool, pApp->pcCountry));
                        }
                        else
                        if (strncmp(pcTok, "remote_organization=", 20) == 0 ||
                            strncmp(pcTok, "remote-organization=", 20) == 0)
                        {
                            pcTok += 20;
                            if ((pcEnd = strchr(pcTok, ',')))
                                pApp->pcRemoteOrg = ap_pstrndup(parms->pool, pcTok, pcEnd-pcTok);
                            else
                                pApp->pcRemoteOrg = ap_pstrdup(parms->pool, pcTok);
                            pcTok += strlen(pApp->pcRemoteOrg);
                            pApp->pcRemoteOrg = ap_psprintf(parms->pool, "&remote_organization=%s",
                                aselect_filter_url_encode(parms->pool, pApp->pcRemoteOrg));
                        }
                        else
		  if (strncmp(pcTok, "url=", 4) == 0)
		  {
		      pcTok += 4;
                            if ((pcEnd = strchr(pcTok, ',')))
                                pApp->pcRedirectURL = ap_pstrndup(parms->pool, pcTok, pcEnd-pcTok);
                            else
                                pApp->pcRedirectURL = ap_pstrdup(parms->pool, pcTok);
		      pcTok += strlen(pApp->pcRedirectURL);
		  }
                        else    
                        if (strncmp(pcTok, "extra_parameters=", 17) == 0 ||
                            strncmp(pcTok, "extra-parameters=", 17) == 0)
                        {
                            pcTok += 17;
                            if ((pcEnd = strchr(pcTok, ',')))
                                pApp->pcExtra = ap_pstrndup(parms->pool, pcTok, pcEnd-pcTok);
                            else
                                pApp->pcExtra = ap_pstrdup(parms->pool, pcTok);
                            pcTok += strlen(pApp->pcExtra);
                            pApp->pcExtra = ap_psprintf(parms->pool, "&%s",
                                pApp->pcExtra);
                        }
                        else
                        {
                            // Unknown option
                            return ap_psprintf(parms->pool,
                                "A-Select ERROR: Unknown option in application %s near \"%s\"", 
                                pApp->pcAppId, pcTok);
                        }
                        if (*pcTok)
                        {
                            if (*pcTok != ',')
                                return ap_psprintf(parms->pool,
                                    "A-Select ERROR: Error in application %s options, near \"%s\"", 
                                    pApp->pcAppId, pcTok);
                            ++pcTok;
                        }                        
                    }
                }
                // Success!
                pConfig->iAppCount++;
            }
            else
            {
                return "A-Select ERROR: Out of memory while adding applications";
            }
        }
        else
        {
            return "A-Select ERROR: Reached max possible application IDs";
        }
    }
    else
    {
        return "A-Select ERROR: Internal error: missing configuration object";
    }

    return NULL;
}

// Bauke: added
// Read all attributes that must be passed in the HTML header from the config file
//
static const char *
aselect_filter_add_attribute(cmd_parms *parms, void *mconfig, const char *arg)
{
	PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
	char **pAttr;

        if (pConfig) {
		if (pConfig->iAttrCount < ASELECT_FILTER_MAX_ATTR) {
			TRACE1("aselect_filter_add_attribute:: %d", pConfig->iAttrCount);
			pAttr = &pConfig->pAttrFilter[pConfig->iAttrCount];
			*pAttr = ap_pstrdup(parms->pool, arg);
			TRACE1("aselect_filter_add_attribute:: %s", *pAttr);
			pConfig->iAttrCount++;
                }
                else {
			return "A-Select ERROR: Reached max possible Attribute Filters";
                }
        }
        else {
                return "A-Select ERROR: Internal error when setting add_attribute";
        }
        return NULL;
}

static const char *aselect_filter_set_redirection_mode(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    char *pcMode;
    if (pConfig){
        if ((pcMode = ap_pstrdup(parms->pool, arg))){
            if (strcasecmp(pcMode, "app") == 0){
                                pConfig->iRedirectMode = ASELECT_FILTER_REDIRECT_TO_APP;
                        }
                        else if (strcasecmp(pcMode, "full") == 0){
                                pConfig->iRedirectMode = ASELECT_FILTER_REDIRECT_FULL;
                        }
                        else{
                return "A-Select ERROR: Invalid argument to aselect_filter_set_redirect_mode";
            }
            TRACE2("aselect_filter_set_redirect_mode:: %d (%s)", pConfig->iRedirectMode,
		    (pConfig->iRedirectMode == ASELECT_FILTER_REDIRECT_TO_APP) ? "app" : "full");
        }
        else{
            return "A-Select ERROR: Internal error while setting redirect_mode";
        }
    }
    return NULL;
}

static const char *
aselect_filter_set_html_error_template(cmd_parms *parms, void *mconfig, const char *arg)
{
        PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
        FILE    *file;
        fpos_t  fpos;
        int     ipos;
        char    cLine[100];
        char    *pcFile;

        if (pConfig) {
                if ((pcFile = ap_pstrdup(parms->pool, arg))) {
                        TRACE1("aselect_filter_set_html_error_template:: %s", pcFile);
                        if ((file = fopen(pcFile, "r"))) {
                                if (fseek(file, 0, SEEK_END) == 0) {
                                        if (fgetpos(file, &fpos) == 0) {
                                                memcpy(&ipos, &fpos, sizeof(ipos));
                                                TRACE1("aselect_filter_set_html_error_template:: size of template: %d", ipos);
                                                if (fseek(file, 0, SEEK_SET) == 0) {
                                                        if ((pConfig->pcErrorTemplate = (char*) ap_palloc(parms->pool, ipos))) {
                                                                memset(pConfig->pcErrorTemplate, 0, sizeof(ipos));
                                                                while (fgets(cLine, sizeof(cLine), file) != NULL)
                                                                        strcat(pConfig->pcErrorTemplate, cLine);
                                                        }
                                                        else {
                                                                TRACE("aselect_filter_set_html_error_template:: failed to allocate mem for pConfig->pcErrorTemplate");
                                                                fclose(file);
                                                                return "A-Select ERROR: Internal error when setting html_error_template file";
                                                        }
                                                }
                                                else {
                                                        TRACE("aselect_filter_set_html_error_template:: fseek(SEEK_SET) failed");
                                                        fclose(file);
                                                        return "A-Select ERROR: Internal error when setting html_error_template file";
                                                }
                                        }
                                        else {
                                                fclose(file);
                                                TRACE("aselect_filter_set_html_error_template:: fgetpos failed");
                                                return "A-Select ERROR: Internal error when setting html_error_template file";
                                        }
                                }
                                else {
                                        TRACE("aselect_filter_set_html_error_template:: fseek(SEEK_END) failed");
                                        fclose(file);
                                        return "A-Select ERROR: Internal error when setting html_error_template file";
                                }
                                fclose(file);
                        }
                        else {
                                TRACE("aselect_filter_set_html_error_template:: fopen failed");
                                return "A-Select ERROR: Could not open html_error_template";
                        }
                }
                else {
                        return "A-Select ERROR: Internal error when setting html_error_template file";
                }
        }
        else {
                return "A-Select ERROR: Internal error when setting html_error_template file";
        }
        return NULL;
}

// Bauke, 20080928, Logout Template added
// www.anoigo.nl
static const char *aselect_filter_set_html_logout_template(cmd_parms *parms, void *mconfig, const char *arg)
{
	char *funName = "aselect_filter_set_html_logout_template";
        PASELECT_FILTER_CONFIG pConfig;
        FILE    *file;
        fpos_t  fpos;
        int     ipos;
        char    cLine[100];
        char    *pcFile;

        pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
        if (!pConfig) {
                return "A-Select ERROR: Internal error when setting html_error_template file";
        }
	pcFile = ap_pstrdup(parms->pool, arg);
	if (!pcFile) {
		return "A-Select ERROR: Internal error when setting html_error_template file";
	}
	TRACE2("%s:: %s", funName, pcFile);
	file = fopen(pcFile, "r");
	if (!file) {
		TRACE1("%s:: fopen failed", funName);
		return "A-Select ERROR: Could not open html_error_template";
	}
	if (fseek(file, 0, SEEK_END) != 0) {
		TRACE1("%s:: fseek(SEEK_END) failed", funName);
		fclose(file);
		return "A-Select ERROR: Internal error when setting html_error_template file";
	}
	if (fgetpos(file, &fpos) != 0) {
		fclose(file);
		TRACE1("%s:: fgetpos failed", funName);
		return "A-Select ERROR: Internal error when setting html_error_template file";
	}
	memcpy(&ipos, &fpos, sizeof(ipos));
	TRACE2("%s:: size of template: %d", funName, ipos);
	if (fseek(file, 0, SEEK_SET) != 0) {
		TRACE1("%s:: fseek(SEEK_SET) failed", funName);
		fclose(file);
		return "A-Select ERROR: Internal error when setting html_error_template file";
	}
	if ((pConfig->pcLogoutTemplate = (char*) ap_palloc(parms->pool, ipos))) {
		memset(pConfig->pcLogoutTemplate, 0, sizeof(ipos));
		while (fgets(cLine, sizeof(cLine), file) != NULL)
			strcat(pConfig->pcLogoutTemplate, cLine);
	}
	else {
		TRACE1("%s:: failed to allocate mem for pConfig->pcLogoutTemplate", funName);
		fclose(file);
		return "A-Select ERROR: Internal error when setting html_error_template file";
	}
	fclose(file);
        return NULL;
}

static const char *
aselect_filter_set_use_aselect_bar(cmd_parms *parms, void *mconfig, const char *arg)
{
        PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
        char                    *pcUseASelectBar;

        if (pConfig)
        {
                if ((pcUseASelectBar = ap_pstrdup(parms->pool, arg)))
                {
                        TRACE1("aselect_filter_set_use_aselect_bar:: %s", pcUseASelectBar);
                        pConfig->bUseASelectBar = FALSE;

                        if (strcasecmp(pcUseASelectBar, "1") == 0)
                                pConfig->bUseASelectBar = TRUE;
                }
                else
                {
                        return "A-Select ERROR: Internal error when setting use_aselect_bar";
                }
        }
        else
        {
                return "A-Select ERROR: Internal error when setting use_aselect_bar";
        }

        return NULL;
}

// Bauke 20081108: added
// Boolean to activate URL escape sequence removal
//
static const char * aselect_filter_secure_url(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    char *pcSecureUrl;

    if (pConfig) {
	if ((pcSecureUrl = ap_pstrdup(parms->pool, arg))) {
	    TRACE1("aselect_filter_secure_url:: %s", pcSecureUrl);
	    pConfig->bSecureUrl = TRUE;  // the default
	    if (strcmp(pcSecureUrl, "0") == 0)
		pConfig->bSecureUrl = FALSE;
	}
	else {
	    return "A-Select ERROR: Internal error when setting secure_url";
	}
    }
    else {
	return "A-Select ERROR: Internal error when setting secure_url";
    }
    return NULL;
}

static const char * aselect_filter_pass_attributes(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    char *pcPassAttr;

    if (pConfig) {
	if ((pcPassAttr = ap_pstrdup(parms->pool, arg))) {
	    TRACE1("aselect_filter_pass_attributes:: %s", pcPassAttr);
	    pConfig->pcPassAttributes[0] = '\0';
	    if (strchr(pcPassAttr, 'c') != 0)
		strcat(pConfig->pcPassAttributes,"c");
	    if (strchr(pcPassAttr, 'q') != 0)
		strcat(pConfig->pcPassAttributes,"q");
	    if (strchr(pcPassAttr, 'h') != 0)
		strcat(pConfig->pcPassAttributes,"h");
	    if (strchr(pcPassAttr, 't') != 0)
		strcat(pConfig->pcPassAttributes,"t");
	}
	else {
	    return "A-Select ERROR: Internal error when setting pass_attributes";
	}
    }
    else {
	return "A-Select ERROR: Internal error when setting pass_attributes";
    }
    return NULL;
}

#ifdef APACHE_13_ASELECT_FILTER
//
// Registered handlers that can be called for this module
//
static handler_rec aselect_filter_handlers[] =
{
    { "aselect_filter_handler", aselect_filter_handler },
    {NULL}
};

//
// Registered cmds to call from httpd.conf
//
static const command_rec
aselect_filter_cmds[] = 
{
    { "aselect_filter_set_agent_address", 
        aselect_filter_set_agent_address, 
        NULL,
        RSRC_CONF,
        TAKE1,
        "Usage aselect_filter_set_agent_address <ip or dns name of A-Select Agent>, example: aselect_filter_set_agent_address \"localhost\"" },
    { "aselect_filter_set_agent_port", 
        aselect_filter_set_agent_port, 
        NULL,
        RSRC_CONF,
        TAKE1,
        "Usage aselect_filter_set_agent_port <port of A-Select Agent>, example: aselect_filter_set_agent_port \"1495\"" },
    { "aselect_filter_add_secure_app",
        aselect_filter_add_secure_app,
        NULL,
        RSRC_CONF,
        TAKE3,
        "Usage aselect_filter_add_secure_app <location> <application id> <flags>, example: aselect_filter_add_secure_app \"///secure///\" \"app1\" \"forced-logon\"" },
    { "aselect_filter_add_authz_rule",
        aselect_filter_add_authz_rule,
        NULL,
        RSRC_CONF,
        TAKE3,
        "Usage aselect_filter_add_authz_rule <application id> <target uri> <condition>, example: aselect_filter_add_authz_rule \"app1\" \"*\" \"role=student\"" },

    { "aselect_filter_set_html_error_template", aselect_filter_set_html_error_template,
        NULL, RSRC_CONF, TAKE1,
        "Usage aselect_filter_set_html_error_template <path to template html page>, example: aselect_filter_set_html_error_template \"///usr//local//apache//aselect//error.html\""
    },
    { "aselect_filter_set_html_logout_template", aselect_filter_set_html_logout_template,
        NULL, RSRC_CONF, TAKE1,
        "Usage aselect_filter_set_html_logout_template <path to template html page>, example: aselect_filter_set_html_logout_template \"///usr//local//apache//aselect//logout.html\""
    },

    { "aselect_filter_set_use_aselect_bar",
        aselect_filter_set_use_aselect_bar,
        NULL,
        RSRC_CONF,
        TAKE1,
        "Usage aselect_filter_set_use_aselect_bar <on or off>, example: aselect_filter_set_use_aselect_bar on" },
    { "aselect_filter_set_redirect_mode",
        aselect_filter_set_redirection_mode,
        NULL,
        RSRC_CONF,
        TAKE1,
        "Usage aselect_filter_redirect_mode <app | full>, example: aselect_filter_redirect_mode \"app\"" },

// Bauke: added 2 entries
    { "aselect_filter_secure_url", aselect_filter_secure_url,
        NULL, RSRC_CONF, TAKE1,
        "Usage aselect_filter_secure_url < 1 | 0 >, example: aselect_filter_secure_url \"1\"" },

    { "aselect_filter_pass_attributes", aselect_filter_pass_attributes,
        NULL, RSRC_CONF, TAKE1,
        "Usage aselect_filter_pass_attributes < c | q | h >, example: aselect_filter_pass_attributes \"ch\"" },

    { "aselect_filter_add_attribute", aselect_filter_add_attribute,
        NULL, RSRC_CONF, TAKE1,
        "Usage aselect_filter_add_attribute < attribute filter spec >, example: aselect_filter_add_attribute \"uid,cn,user_id\"" },

    { NULL }
};

//
// Main export structure containing all the entry points for this module
//
module MODULE_VAR_EXPORT aselect_filter_module =
{
    STANDARD_MODULE_STUFF,
    aselect_filter_init,    // module initializer
    NULL,                   // per-dir config creator
    NULL,                   // dir config merger
    aselect_filter_create_config,   // server config creator
    NULL,                   // server config merger
    aselect_filter_cmds,    // command table
    NULL,                   // [9] content handlers
    NULL,                   // [2] URI-to-filename translation
    NULL,                   // [5] check/validate user_id
    NULL,                   // [6] check user_id is valid here
    aselect_filter_handler, // [4] check access by host address
    NULL,                   // [7] MIME type checker/setter
    NULL,                   // [8] fixups
    NULL,                   // [10] logger
    NULL,                   // [3] header parser
    NULL,                   // process initialization
    NULL,                   // process exit/cleanup
    NULL                    // [1] post read_request handling
};

#else // #ifdef APACHE_13_ASELECT_FILTER

//
// Registered cmds to call from httpd.conf
//
static const command_rec
aselect_filter_cmds[] = 
{
    AP_INIT_TAKE1( "aselect_filter_set_agent_address", 
        aselect_filter_set_agent_address, 
        NULL,
        RSRC_CONF,
        "Usage aselect_filter_set_agent_address <ip or dns name of A-Select Agent>, example: aselect_filter_set_agent_address \"localhost\"" ),
    AP_INIT_TAKE1( "aselect_filter_set_agent_port", 
        aselect_filter_set_agent_port, 
        NULL,
        RSRC_CONF,
        "Usage aselect_filter_set_agent_port <port of A-Select Agent>, example: aselect_filter_set_agent_port \"1495\"" ),
    AP_INIT_TAKE3( "aselect_filter_add_secure_app",
        aselect_filter_add_secure_app,
        NULL,
        RSRC_CONF,
        "Usage aselect_filter_add_secure_app <location> <application id> <flags>, example: aselect_filter_add_secure_app \"///secure///\" \"app1\" \"forced-logon\"" ),
    AP_INIT_TAKE3( "aselect_filter_add_authz_rule",
        aselect_filter_add_authz_rule,
        NULL,
        RSRC_CONF,
        "Usage aselect_filter_add_authz_rule <application id> <target uri> <condition>, example: aselect_filter_add_authz_rule \"app1\" \"*\" \"role=student\"" ),

    AP_INIT_TAKE1( "aselect_filter_set_html_error_template", aselect_filter_set_html_error_template,
        NULL, RSRC_CONF,
        "Usage aselect_filter_set_html_error_template <path to template html page>, example: aselect_filter_set_html_error_template \"///usr//local//apache//aselect//error.html\"" ),
    AP_INIT_TAKE1( "aselect_filter_set_html_logout_template", aselect_filter_set_html_logout_template,
        NULL, RSRC_CONF,
        "Usage aselect_filter_set_html_logout_template <path to template html page>, example: aselect_filter_set_html_logout_template \"///usr//local//apache//aselect//logout.html\"" ),

    AP_INIT_TAKE1( "aselect_filter_set_use_aselect_bar",
        aselect_filter_set_use_aselect_bar,
        NULL,
        RSRC_CONF,
        "Usage aselect_filter_set_use_aselect_bar <on or off>, example: aselect_filter_set_use_aselect_bar on" ),
    AP_INIT_TAKE1("aselect_filter_set_redirect_mode",
        aselect_filter_set_redirection_mode,
        NULL,
        RSRC_CONF,
        "Usage aselect_filter_redirect_mode <app | full>, example: aselect_filter_redirect_mode \"app\""),

// Bauke: added 3 entries
    AP_INIT_TAKE1("aselect_filter_secure_url", aselect_filter_secure_url,
        NULL, RSRC_CONF,
        "Usage aselect_filter_secure_url < 0 | 1 >, example: aselect_filter_secure_url \"1\""),

    AP_INIT_TAKE1("aselect_filter_pass_attributes", aselect_filter_pass_attributes,
        NULL, RSRC_CONF,
        "Usage aselect_filter_pass_attributes < c | q | h >, example: aselect_filter_pass_attributes \"ch\"" ),

    AP_INIT_TAKE1("aselect_filter_add_attribute", aselect_filter_add_attribute,
        NULL, RSRC_CONF,
        "Usage aselect_filter_add_attribute < 0 | 1 >, example: aselect_filter_add_attribute \"0\""),

    { NULL }
};

void *
aselect_filter_create_server_config( apr_pool_t *pPool, server_rec *pServer )
{
    PASELECT_FILTER_CONFIG  pConfig = NULL;

    TRACE( "aselect_filter_create_config" );
    if( ( pConfig = ( PASELECT_FILTER_CONFIG ) apr_palloc( pPool, sizeof( ASELECT_FILTER_CONFIG ) ) ) )
    {
        memset( pConfig, 0, sizeof( ASELECT_FILTER_CONFIG ) );
    }
    else
    {
        TRACE( "aselect_filter_create_config::ERROR:: could not allocate memory for pConfig" );
        pConfig = NULL;
    }

    return pConfig;
}

void
aselect_filter_register_hooks( apr_pool_t *p )
{

    TRACE( "aselect_filter_register_hooks" );
    ap_hook_post_config( aselect_filter_init, NULL, NULL, APR_HOOK_MIDDLE );
    ap_hook_access_checker( aselect_filter_handler, NULL, NULL, APR_HOOK_MIDDLE );
}

module AP_MODULE_DECLARE_DATA
aselect_filter_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                   // per-directory config creator
    NULL,                   // dir config merger
    aselect_filter_create_server_config,    // server config creator
    NULL,                   // server config merger
    aselect_filter_cmds,            // command table
    aselect_filter_register_hooks,      //  set up other request processing hooks
};

#endif // #ifdef APACHE_13_ASELECT_FILTER

