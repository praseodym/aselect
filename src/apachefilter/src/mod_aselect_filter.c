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
//
// Bauke 20120526: removed Apache 1.3 code
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
module AP_MODULE_DECLARE_DATA aselect_filter_module;


//static handler_rec      aselect_filter_handlers[];
static const command_rec    aselect_filter_cmds[];

char *version_number = "====subversion_244====";

// -----------------------------------------------------
// Functions 
// -----------------------------------------------------

int aselect_filter_upload_all_rules(PASELECT_FILTER_CONFIG pConfig, server_rec *pServer, pool *pPool, TIMER_DATA *pt);
int  aselect_filter_upload_authz_rules(PASELECT_FILTER_CONFIG pConfig, server_rec *pServer, pool *pPool, PASELECT_APPLICATION pApp, TIMER_DATA *pt);
char *aselect_filter_verify_ticket(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcTicket, char *pcUID,
				    char *pcOrganization, char *pcAttributes, char *language, TIMER_DATA *pt);
char *aselect_filter_kill_ticket(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcTicket, TIMER_DATA *pt);
char *aselect_filter_auth_user(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcAppUrl, TIMER_DATA *pt);
char *aselect_filter_verify_credentials(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcRID,
					char *pcCredentials, char *applicationArguments, TIMER_DATA *pt);
static int      aselect_filter_handler(request_rec *pRequest );
//static void *   aselect_filter_create_config(pool *pPool, server_rec *pServer );
static int      aselect_filter_verify_config(request_rec *pRequest, PASELECT_FILTER_CONFIG pConfig );
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
static const char *aselect_filter_add_public_app(cmd_parms *parms, void *mconfig, const char *arg);
static const char *aselect_filter_set_logfile(cmd_parms *parms, void *mconfig, const char *arg );
static const char *aselect_filter_added_security(cmd_parms *parms, void *mconfig, const char *arg );
static const char * aselect_filter_set_sensor_address(cmd_parms *parms, void *mconfig, const char *arg );
static const char * aselect_filter_set_sensor_port(cmd_parms *parms, void *mconfig, const char *arg );

static char * aselect_filter_attributes(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcTicket,
					char *pcUid, char *pcOrganization, TIMER_DATA *pt);
static int aselect_filter_passAttributesInUrl(int iError, char *pcAttributes, pool *pPool, request_rec *pRequest,
	PASELECT_FILTER_CONFIG pConfig, char *pcTicketIn, char *pcUIDIn, char *pcOrganizationIn,
	char *pcRequestLanguage, table *headers_in, TIMER_DATA *pt);
static void aselect_filter_removeUnwantedCharacters(char *args);
static char *aselect_filter_findNoCasePattern(const char *text, const char *pattern);
static void splitAttrFilter(char *attrFilter, char *condName, int condLen,
			    char *ldapName, int ldapLen, char *attrName, int attrLen);
static char *replaceAttributeValues(pool *pPool, char *pcAttributes, char *text, int bUrlDecode);
static int conditionIsTrue(pool *pPool, char *pcAttributes, char *condName);
static char *extractAttributeNames(pool *pPool, char *text, char *paramNames);
static char *getRequestedAttributes(pool *pPool, PASELECT_FILTER_CONFIG pConfig);

//
// Called once during the module initialization phase.
// can be used to setup the filter configuration 
//
int aselect_filter_init(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *pPool, server_rec *pServer)
{
    int i;
    char pcMessage[2048];
    TRACE1("aselect_filter_init: { %x", pServer);
    TRACE3("aselect_filter_init: %s|%s|%s", pServer->error_fname, pServer->server_hostname, pServer->server_scheme);
    PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG)ap_get_module_config(pServer->module_config, &aselect_filter_module);

    TRACE1("aselect_filter_init: %x read", pServer);
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, pServer, "ASELECT_FILTER:: initializing");

    if (pConfig->pcAddedSecurity[0] == '\0')
	strcat(pConfig->pcAddedSecurity, "c");  // add Secure & HttpOnly to cookies
    TRACE1("aselect_filter_init: added_security=%s", pConfig->pcAddedSecurity);

    if (pConfig) { // 20091223: Bauke, added
	aselect_filter_trace_logfilename(pConfig->pcLogFileName);
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

	if (!aselect_filter_upload_all_rules(pConfig, pServer, pPool, NULL))
	    return -1;
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, pServer,
		ap_psprintf(pPool, "ASELECT_FILTER:: secure apps: %d, public apps: %d, attributes: %d", 
		pConfig->iAppCount, pConfig->iPublicAppCount, pConfig->iAttrCount));
    }
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, pServer, "ASELECT_FILTER:: done");
    TRACE1("aselect_filter_init: } %x done", pServer);
    return 0;
}

//
// Bauke: needed this stuff to be able to send the rules again
//
int aselect_filter_upload_all_rules(PASELECT_FILTER_CONFIG pConfig, server_rec *pServer, pool *pPool, TIMER_DATA *pt)
{
    int i;
    PASELECT_APPLICATION pApp;

    TRACE1("ASELECT_FILTER:: AppCount=%d", pConfig->iAppCount);
    for (i=0; i<pConfig->iAppCount; i++) {
	pApp = &pConfig->pApplications[i];
	TRACE4("ASELECT_FILTER:: added %s at %s %s%s", pApp->pcAppId, pApp->pcLocation,
		pApp->bEnabled ? "" : "(disabled)", pApp->bForcedLogon ? "(forced logon)" : "");

	if (aselect_filter_upload_authz_rules(pConfig, pServer, pPool, pApp, pt)) {
	    TRACE2("ASELECT_FILTER:: registered %d authZ rules for %s", pApp->iRuleCount, pApp->pcAppId);
	}
	else
	    return 0; // not ok
    }
    return 1; // ok
}

// Upload authorization rule for a single application
int aselect_filter_upload_authz_rules(PASELECT_FILTER_CONFIG pConfig, server_rec *pServer, pool *pPool, PASELECT_APPLICATION pApp, TIMER_DATA *pt)
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
    length = 100 + strlen(pAppId);
    for (i=0; i<pApp->iRuleCount; i++) {
        length += 32 + strlen(pApp->pTargets[i]) + strlen(pApp->pConditions[i]);
    }
    
    // Create request
    pRequest = (char *)ap_palloc(pPool, length);
    if (pRequest)
    {
        strcpy(pRequest, "request=set_authorization_rules&app_id=");
        strcat(pRequest, pAppId);
        strcat(pRequest, "&usi=");
        strcat(pRequest, timer_usi(pPool, pt));
        for (i=0; i<pApp->iRuleCount; i++)
        {
            ap_snprintf(pRuleId, sizeof(pRuleId), "r%d", i);
            strcat(pRequest, "&rules%5B%5D=");  // []
            strcat(pRequest, pRuleId);
            strcat(pRequest, "%3B");  // ;
            strcat(pRequest, pApp->pTargets[i]);
            strcat(pRequest, "%3B");  // ;
            strcat(pRequest, pApp->pConditions[i]);
        }
        strcat(pRequest, "\r\n");
        
        TRACE1("aselect_filter_upload_authz_rules: sending: %s", pRequest);
        pcResponse = aselect_filter_send_request(pServer, pPool, pConfig->pcASAIP, pConfig->iASAPort, pRequest, strlen(pRequest), pt, 1);
        if (pcResponse == NULL) {
            // Could not send request, error already logged
            return 0;
        }
        //TRACE1("aselect_filter_upload_authz_rules: response: %s", pcResponse);
        iRet = aselect_filter_get_error(pPool, pcResponse);
        if (iRet != 0) {
	    TRACE1("ASELECT_FILTER:: Agent returned error %s while uploading authorization rules", pcResponse);
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
char *aselect_filter_verify_ticket(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig,
	char *pcTicket, char *pcUID, char *pcOrganization, char *pcAttributes, char *language, TIMER_DATA *pt)
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
    if (pcAttributes && *pcAttributes) {
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
	    "request=verify_ticket&ticket=%s&app_id=%s&uid=%s&organization=%s&attributes_hash=%s&request_uri=%s&ip=%s%s&usi=%s\r\n", 
	    pcTicket, pConfig->pCurrentApp->pcAppId, pcUID, pcOrganization, 
	    pcSHA1, pcURI, pRequest->connection->remote_ip, langBuf, timer_usi(pPool, pt));
    else // No attribute hash available, so don't ask for an attribute check
	pcSendMessage = ap_psprintf(pPool, 
	    "request=verify_ticket&ticket=%s&app_id=%s&uid=%s&organization=%s&request_uri=%s&ip=%s%s&usi=%s\r\n", 
	    pcTicket, pConfig->pCurrentApp->pcAppId, pcUID, pcOrganization, 
	    pcURI, pRequest->connection->remote_ip, langBuf, timer_usi(pPool, pt));

    ccSendMessage = strlen(pcSendMessage);

    //TRACE2("request(%d): %s", ccSendMessage, pcSendMessage);
    pcResponse = aselect_filter_send_request(pRequest->server, pPool, pConfig->pcASAIP, pConfig->iASAPort,
			pcSendMessage, ccSendMessage, pt, 1);
    return pcResponse;
}

//
// Kills the ticket
//
char *aselect_filter_kill_ticket(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcTicket, TIMER_DATA *pt)
{
    char            *pcSendMessage;
    int             ccSendMessage;
    char            *pcResponse;

    //
    // Create the message
    //
    TRACE("aselect_filter_kill_ticket");
    pcSendMessage = ap_psprintf(pPool, "request=kill_ticket&ticket=%s&app_id=%s&usi=%s\r\n", 
	    aselect_filter_url_encode(pPool, pcTicket), aselect_filter_url_encode(pPool, pConfig->pCurrentApp->pcAppId), timer_usi(pPool, pt));
    ccSendMessage = strlen(pcSendMessage);

    //TRACE2("request(%d): %s", ccSendMessage, pcSendMessage);
    pcResponse = aselect_filter_send_request(pRequest->server, pPool, pConfig->pcASAIP, pConfig->iASAPort,
		    pcSendMessage, ccSendMessage, pt, 1);
    return pcResponse;
}

//
// Request an authentication of a user
//
char *aselect_filter_auth_user(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcAppUrl, TIMER_DATA *pt)
{
    char    *pcSendMessage;
    int     ccSendMessage;
    char    *pcResponse;

    TRACE("aselect_filter_auth_user");

    // Create the message
    pcSendMessage = ap_psprintf(pPool, "request=authenticate&app_url=%s&app_id=%s&forced_logon=%s%s%s%s%s%s%s&usi=%s\r\n", 
        aselect_filter_url_encode(pPool, pcAppUrl), 
        aselect_filter_url_encode(pPool, pConfig->pCurrentApp->pcAppId),
        pConfig->pCurrentApp->bForcedLogon ? "true" : "false",
        pConfig->pCurrentApp->pcUid,
        pConfig->pCurrentApp->pcAuthsp,
        pConfig->pCurrentApp->pcCountry,
        pConfig->pCurrentApp->pcLanguage,
        pConfig->pCurrentApp->pcRemoteOrg,
        pConfig->pCurrentApp->pcExtra, timer_usi(pPool, pt));
    ccSendMessage = strlen(pcSendMessage);
    //TRACE2("request(%d): %s", ccSendMessage, pcSendMessage);

    if ((pcResponse = aselect_filter_send_request(pRequest->server, pPool, pConfig->pcASAIP, pConfig->iASAPort, pcSendMessage, ccSendMessage, pt, 1))) {
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
    char *p, *q, *paramNames = ",";
    char condName[400], ldapName[400];
    char attrName[200];
    int i, len;

    for (i = 0; i < pConfig->iAttrCount; i++) {
	//TRACE2("getRequestedAttributes:: %d: %s", i, pConfig->pAttrFilter[i]);
	splitAttrFilter(pConfig->pAttrFilter[i], condName,sizeof(condName), ldapName,sizeof(ldapName), NULL,0);

	// Look in condName and ldapName for [attr,<name>] constructs
	if (ldapName[0] != '\0') {
	    // Decent ldapName present, extract attributes from expression
	    if (ldapName[0] == '\'' && ldapName[strlen(ldapName)-1] == '\'')
		paramNames = extractAttributeNames(pPool, ldapName, paramNames);
	    else {
		// Add ldapName itself, if not present yet
		sprintf(attrName, ",%s,", ldapName);
		if (strstr(paramNames, attrName) == 0)
		    paramNames = ap_psprintf(pPool, "%s%s,", paramNames, ldapName);
	    }
	}
	if (condName[0] != '\0') {
	    paramNames = extractAttributeNames(pPool, condName, paramNames);
	}
    }

    // Remove comma's
    paramNames[strlen(paramNames)-1] = '\0';
    TRACE1("getRequestedAttributes:: %s", paramNames+1);
    return paramNames+1;
}

static char *extractAttributeNames(pool *pPool, char *text, char *paramNames)
{
    char *p, *begin, *end;
    char attrName[200];

    //TRACE1("extractAttributeNames text=%s", text);
    begin = strstr(text, "[attr,");
    for ( ; begin != NULL; begin = strstr(end, "[attr,")) {
	begin += 6;
	end = strchr(begin, ']');
	if (!end)
	    return paramNames;
	if (end-begin < 1)
	    continue;

	// Does the parameter already occur?
	sprintf(attrName, ",%.*s,", end-begin, begin);
	if (strstr(paramNames, attrName) == 0)
	    paramNames = ap_psprintf(pPool, "%s%.*s,", paramNames, end-begin, begin);
    }
    //TRACE1("extractAttributeNames params=%s", paramNames);
    return paramNames;
}

//
// Verify the credentials
// sends the RID and the credentials to the Aselect Agent for verification
// Bauke 20081201: added saml_attributes
// Bauke 20100521: added aselect_app_args
//
char *aselect_filter_verify_credentials(request_rec *pRequest, pool *pPool,
	    PASELECT_FILTER_CONFIG pConfig, char *pcRID, char *pcCredentials,
	    char *applicationArguments, TIMER_DATA *pt)
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
    // 20100521, Bauke: added, application args secured by Agent
    pcSendMessage = ap_psprintf(pPool, "request=verify_credentials&aselect_app_args=%s&rid=%s&aselect_credentials=%s%s%s&usi=%s\r\n", 
	    aselect_filter_url_encode(pPool, applicationArguments),
	    aselect_filter_url_encode(pPool, pcRID),
	    aselect_filter_url_encode(pPool, pcCredentials),
	    (attrNames)? "&saml_attributes=": "", (attrNames)? attrNames: "", timer_usi(pPool, pt));
    ccSendMessage = strlen(pcSendMessage);

    //TRACE2("request(%d): %s", ccSendMessage, pcSendMessage);
    pcResponse = aselect_filter_send_request(pRequest->server, pPool, pConfig->pcASAIP,
                            pConfig->iASAPort, pcSendMessage, ccSendMessage, pt, 1);

    return pcResponse;
}

//
// Bauke: Added:
// Retrieve Attribute values from the Agent
//
char *aselect_filter_attributes(request_rec *pRequest, pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcTicket, char *pcUid, char *pcOrganization, TIMER_DATA *pt)
{
    char    *pcSendMessage;
    int     ccSendMessage;
    char    *pcResponse;

    TRACE("aselect_filter_attributes");
    //
    // Create the message
    //
    pcSendMessage = ap_psprintf(pPool, "request=attributes&ticket=%s&uid=%s&organization=%s&usi=%s\r\n", 
		aselect_filter_url_encode(pPool, pcTicket), aselect_filter_url_encode(pPool, pcUid),
		aselect_filter_url_encode(pPool, pcOrganization), timer_usi(pPool, pt));
    ccSendMessage = strlen(pcSendMessage);

    //TRACE2("request(%d): %s", ccSendMessage, pcSendMessage);
    if ((pcResponse = aselect_filter_send_request(pRequest->server, pPool, pConfig->pcASAIP, pConfig->iASAPort, pcSendMessage, ccSendMessage, pt, 1)))
    {
        //TRACE1("response message: %s", pcResponse);
    }
    else { // could not send request to A-Select Agent
        pcResponse = NULL;
    }
    return pcResponse;
}


static int aselect_filter_verify_config(request_rec *pRequest, PASELECT_FILTER_CONFIG pConfig)
{
    if (!pConfig) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pRequest, "SIAM:: no config at all");
        return ASELECT_FILTER_ERROR_CONFIG;
    }
    if (pConfig->bConfigError) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pRequest, "SIAM:: config error detected (old)");
        return ASELECT_FILTER_ERROR_CONFIG;
    }
    if (!pConfig->pcASAIP) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pRequest, "SIAM:: no agent_address");
        return ASELECT_FILTER_ERROR_CONFIG;
    }
    if (strlen(pConfig->pcASAIP) <= 0) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pRequest, "SIAM:: no agent_address value");
	return ASELECT_FILTER_ERROR_CONFIG;
    }

    if (pConfig->iASAPort == 0) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pRequest, "SIAM:: no agent_port");
        return ASELECT_FILTER_ERROR_CONFIG;
    }

    if (pConfig->iAppCount == 0) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pRequest, "SIAM:: no applications specified (warning)");
        //return ASELECT_FILTER_ERROR_CONFIG;
    }

    if (!pConfig->pcErrorTemplate || strlen(pConfig->pcErrorTemplate) <= 0) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pRequest, "SIAM:: no error_template");
	return ASELECT_FILTER_ERROR_CONFIG;
    }

    if (!pConfig->pcLogoutTemplate || strlen(pConfig->pcLogoutTemplate) <= 0) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pRequest, "SIAM:: no logout_template");
	return ASELECT_FILTER_ERROR_CONFIG;
    }
    return ASELECT_FILTER_ERROR_OK;
}

// Extract parameters that must be passed to the application from all arguments
//
char *extractApplicationParameters(pool *pPool, char *arguments)
{
    char *pcStrippedParams  = NULL;
    int bFirstParam = TRUE;
    char *pcTmp = strtok(arguments, "?&");
    char *pcTmp2;

    while (pcTmp != NULL) {
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
    return (pcStrippedParams != NULL)? pcStrippedParams: "";
}

//
// Main handler, will handle cookie checking and redirection
//
static int aselect_filter_handler(request_rec *pRequest)
{
    int ok;
    int iRet = FORBIDDEN; // 402
    int iError = ASELECT_FILTER_ERROR_OK;
    int iAction = ASELECT_FILTER_ACTION_ACCESS_DENIED;
    table *headers_in = pRequest->headers_in;
    table *headers_out = pRequest->headers_out;
    PASELECT_FILTER_CONFIG  pConfig;
    char *pcTicketIn, *pcTicketOut = NULL;
    char *pcUIDIn, *pcUIDOut = NULL;
    char *pcOrganizationIn, *pcOrganizationOut = NULL;
    char *pcAttributesIn;
    char *pcTicket;
    char *pcCredentials;
    char *pcRID;
    char *pcAppUrl;
    char *pcCookie, *pcCookie2, *pcCookie3, *pcCookie4;
    char *pcASUrl;
    char *pcASelectServer;
    char *pcResponseVT, *pcResponseAU;
    char *pcResponseCred;
    pool *pPool = NULL;
    char *pcUrl;
    char *pcRequest;
    char *pcASelectAppURL, *pcASelectServerURL;
    char *pcResponseKill;
    char *pcTmp, *pcTmp2;
    char *pcStrippedParams;
    char *pcAttributes = NULL;
    char *pcRequestLanguage = NULL;
    char *addedSecurity = "";
    char *securedAselectAppArgs = NULL;
    char *passUsiAttribute = NULL; 
    int bFirstParam;
    int rc, isSecure = 0;
    TIMER_DATA timer_data;

    ap_log_error(APLOG_MARK, APLOG_INFO, pRequest->server, ap_psprintf(pRequest->pool, "SIAM:: URI - %s %s", pRequest->uri, pRequest->args));
    TRACE2("---- { GET %s %s", pRequest->uri, pRequest->args);
    // START TIMER
    timer_data.td_type = 0;
    timer_start(&timer_data);
    ap_table_do(aselect_filter_print_table, pRequest, headers_in, NULL);

    //
    // Select which pool to use
    //
    if ((apr_pool_create(&pPool, pRequest->pool)) != APR_SUCCESS) {
        // Could not allocate pool
        TRACE("aselect_filter_handler: Could not allocate memory pool");
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pRequest, "SIAM:: could allocate memory pool");
	goto finish_filter_handler;  // only goto's to routine exit point
    }

    // NOTE: the application ticket is a cookie, check if the browser can handle cookies else we run into a loop
    // check cookie, no cookie, validate_user, set cookie, check cookie, no cookie.... and so on
    
    // Read config data
    pConfig = (PASELECT_FILTER_CONFIG)ap_get_module_config(pRequest->server->module_config, &aselect_filter_module);
    if (!pConfig) {
        // Something went wrong, access denied
        TRACE("Could not get module config data");
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pRequest, "SIAM:: could not retrieve configuration data");
	goto finish_filter_handler;
    }
    else { // Verify configuration
	TRACE2("IP=%s Port=%d", (pConfig->pcASAIP)? pConfig->pcASAIP: "NULL", pConfig->iASAPort);
        if (aselect_filter_verify_config(pRequest, pConfig) != ASELECT_FILTER_ERROR_OK) {
            TRACE("Invalid configuration data");
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pRequest, "SIAM:: invalid configuration data");
	    goto finish_filter_handler;
        }
    }

    /* Return codes are:
       DECLINED -1 **< Module declines to handle
       DONE -2     **< Module has served the response completely, it's safe to die() with no more output
       OK 0        **< Module has handled this stage */

    // 20110129, Bauke added public directories
    // Code uses 'secure' as default (all public directories must be enumerated)

    // 20120530, Bauke: new mechanism to choose public/secure using match length
    // 20120608: default is secure
    //rc = aselect_filter_check_app_uri(pPool, pConfig, pRequest->uri);
    rc = 1;
    TRACE2("Return \"%s\" rc=%d", pRequest->uri, rc);
    if (rc == 0) {  // public
	ap_log_error(APLOG_MARK, APLOG_INFO, pRequest->server,
	    ap_psprintf(pRequest->pool, "SIAM:: Public - %s", pRequest->uri));
        TRACE1("\"%s\" is a public directory", pRequest->uri);
	iRet = OK;
	goto finish_filter_handler; // we don't want to do anything with this request
    }
    // else 1="secure" or -1="not found"
    // 20120530 end

    /*
    if (aselect_filter_is_public_app(pPool, pConfig, pRequest->uri) == ASELECT_FILTER_ERROR_OK) {
	ap_log_error(APLOG_MARK, APLOG_INFO, pRequest->server,
	    ap_psprintf(pRequest->pool, "SIAM:: Public - %s", pRequest->uri));
        TRACE1("\"%s\" is a public directory", pRequest->uri);
	iRet = OK;
	goto finish_filter_handler; // we don't want to do anything with this request
    }

    // Check if we are in a protected dir
    // This function points the global pConfig->pCurrentApp to the requested app
    //
    if (aselect_filter_verify_directory(pPool, pConfig, pRequest->uri) == ASELECT_FILTER_ERROR_FAILED) {
        // Not in a protected dir, this should not be possible, but we let the request through anyway
	ap_log_error(APLOG_MARK, APLOG_INFO, pRequest->server,
	    ap_psprintf(pRequest->pool, "SIAM:: Disabled - %s", pRequest->uri));
        TRACE1("\"%s\" is not a protected dir (or is disabled)", pRequest->uri);
        iRet = DECLINED;
	goto finish_filter_handler;
    }
    */

    // Serious action, so use a serious type :-)
    timer_data.td_type = 1;

    // 20091114, Bauke: report application language back to the Server
    // TODO: Should look into the POST data as well!
    // Currently callers have to specify the language as an URL parameter
    pcRequestLanguage = aselect_filter_get_param(pPool, pRequest->args, "language=", "&", TRUE);

    //
    // Retrieve the remote_addr
    //
    ap_log_error(APLOG_MARK, APLOG_INFO, pRequest->server,
	ap_psprintf(pRequest->pool, "SIAM:: Secure - %s app=%s", pRequest->uri, pConfig->pCurrentApp->pcAppId));
    TRACE2("\"%s\" is a protected dir, app_id: %s", pRequest->uri, pConfig->pCurrentApp->pcAppId);
    if (pRequest->connection->remote_ip) {
        TRACE1("remote_ip: %s", pRequest->connection->remote_ip);
    }

    TRACE3("==== 1. Start iError=%d iAction=%s, iRet=%s", iError, filter_action_text(iAction), filter_return_text(iRet));
    TRACE3("     (DECLINED=%d DONE=%d FORBIDDEN=%d)", DECLINED, DONE, FORBIDDEN);
    addedSecurity = (strchr(pConfig->pcAddedSecurity, 'c')!=NULL)? " secure; HttpOnly": "";
    if (pcTicketIn = aselect_filter_get_cookie(pPool, headers_in, "JSESSIONID="))
        TRACE1("aselect_filter_handler: JSESSIONID: %s", pcTicketIn);
    //
    // Check for application ticket
    //
    pcTicketIn = aselect_filter_get_cookie(pPool, headers_in, "aselectticket=");
    if (pcTicketIn) {
        //
        // Look for a valid ticket
        //
        TRACE1("aselect_filter_handler: found ticket: %s", pcTicketIn);
        if ((pcUIDIn = aselect_filter_get_cookie(pPool, headers_in, "aselectuid="))) {
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
		if (1 == 1) {
		    int try;
                    TRACE1("aselect_filter_handler: attributes cookie: %s", pcAttributesIn? pcAttributesIn: "NULL");
                    // Validate ticket
		    // Bauke: added, always send rules
		    //aselect_filter_upload_all_rules(pConfig, pRequest->server, pPool, &timer_data);
		    // 20120527, Bauke: no longer uploading the rules in advance, but upon error message from Agent
		    for (try = 0; try < 2; try++) {
			pcResponseVT = aselect_filter_verify_ticket(pRequest, pPool, pConfig, pcTicketIn,
					pcUIDIn, pcOrganizationIn, pcAttributesIn, pcRequestLanguage, &timer_data);
			// if batch_size < 0, no Agent configuration, ignore Agent
                        iError = aselect_filter_get_error(pPool, pcResponseVT);
			pcTmp = aselect_filter_get_param(pPool, pcResponseVT, "batch_size=", "&", TRUE);
			if (pcTmp != NULL) {  // new Agent too
			    int iBatchSize = atoi(pcTmp);
			    if (iBatchSize >= 0)
				pConfig->iBatchSize = iBatchSize;
			}
			else { // older Agent, does not report batch_size
			    if (iError == ASELECT_FILTER_ASAGENT_ERROR_NOT_AUTHORIZED) // could be caused by absent rules
				iError = ASELECT_FILTER_ASAGENT_ERROR_NO_RULES;  // force rule sending
			}
			if (iError == ASELECT_FILTER_ASAGENT_ERROR_NO_RULES) {
			    aselect_filter_upload_all_rules(pConfig, pRequest->server, pPool, &timer_data);
			    // and try again
			}
			else break;
		    }
		    if (iError == ASELECT_FILTER_ASAGENT_ERROR_NO_RULES)
			iError = ASELECT_FILTER_ASAGENT_ERROR_NOT_AUTHORIZED; // 140
                    if (pcResponseVT) {
			// 20120527, Bauke: use the Agent setting for sending data to LbSensor
			// if batch_size < 0, no Agent configuration, ignore Agent
			pcTmp = aselect_filter_get_param(pPool, pcResponseVT, "batch_size=", "&", TRUE);
			if (pcTmp != NULL) {
			    int iBatchSize = atoi(pcTmp);
			    if (iBatchSize >= 0)
				pConfig->iBatchSize = iBatchSize;
			}
                        if (iError == ASELECT_FILTER_ASAGENT_ERROR_OK) {
                            // User has ticket, ACCESS GRANTED
			    // 20091114, Bauke: Possibly a server language was passed back
			    pcTmp = aselect_filter_get_param(pPool, pcResponseVT, "language=", "&", TRUE);
			    if (pcTmp != NULL) {
				TRACE1("Return language=%s", pcTmp);
			    	pcRequestLanguage = pcTmp;
			    }
			    // 20100521, Bauke: added, application args secured by Agent
			    pcTmp = aselect_filter_get_param(pPool, pcResponseVT, "aselect_app_args=", "&", TRUE);
			    if (pcTmp != NULL) {
				TRACE1("Return aselect_app_args=%s", pcTmp);
				securedAselectAppArgs = pcTmp;
			    }
			    pcTmp = aselect_filter_get_param(pPool, pcResponseVT, "usi=", "&", TRUE);
			    if (pcTmp != NULL) {
				TRACE1("passUsi=%s", pcTmp);
				passUsiAttribute = pcTmp;
			    }
                            iAction = ASELECT_FILTER_ACTION_ACCESS_GRANTED;
                            TRACE("aselect_filter_handler: User has ticket: ACCESS_GRANTED");
                        }
                        else {
			    pRequest->content_type = "text/html";
			    pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s;%s", "aselectticket", pConfig->pCurrentApp->pcLocation, addedSecurity);
			    TRACE1("Delete cookie: %s", pcCookie);
			    ap_table_add(headers_out, "Set-Cookie", pcCookie);
			    ap_send_http_header(pRequest);

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
                                    ap_psprintf(pPool, "ASELECT_FILTER:: aselect_filter_verify_ticket FAILED (%d)", iError));
                            }
                        }
                    }
                }
                else { // Ticket verification failed, check if credentials is valid (if credentials is present)
                    iError = ASELECT_FILTER_ASAGENT_ERROR_CORRUPT_ATTRIBUTES;
                }
            }
            else { // Could not find a inst-id, check if the user has credentials 
                iAction = ASELECT_FILTER_ACTION_VERIFY_CREDENTIALS;
            }
        }
        else { // Could not find a user-id, check if the user has credentials 
            iAction = ASELECT_FILTER_ACTION_VERIFY_CREDENTIALS;
        }
    }
    else { // Could not find a application ticket, check if the user has credentials
        iAction = ASELECT_FILTER_ACTION_VERIFY_CREDENTIALS;
    }

    TRACE3("==== 2. Verify iError=%d iAction=%s, iRet=%s", iError, filter_action_text(iAction), filter_return_text(iRet));
    if (iAction == ASELECT_FILTER_ACTION_VERIFY_CREDENTIALS) {
        //
        // Check for user credentials 
        //
        TRACE1("Verify Credentials, ARGUMENTS: %s", pRequest->args);
        pcCredentials = aselect_filter_get_param(pPool, pRequest->args, "aselect_credentials=", "&", TRUE);
        if (pcCredentials) {
            TRACE1("aselect_credentials: %s", pcCredentials);
            pcRID = aselect_filter_get_param(pPool, pRequest->args, "rid=", "&", TRUE);
            if (pcRID) {
                // Found credentials, now verify them, if ok it returns a ticket
		securedAselectAppArgs = extractApplicationParameters(pPool, pRequest->args);
		// 20100521, Bauke: added, application args will be secured by Agent
                pcResponseCred = aselect_filter_verify_credentials(pRequest, pPool, pConfig, pcRID,
				    pcCredentials, securedAselectAppArgs, &timer_data);
                if (pcResponseCred) {
                    iError = aselect_filter_get_error(pPool, pcResponseCred);
                    if (iError == ASELECT_FILTER_ERROR_INTERNAL)
                        iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;

                    if (iError == ASELECT_FILTER_ASAGENT_ERROR_OK) {
                        // User credentials are ok, set application ticket and let user through
			TRACE1("aselect_credentials, response [%.50s...]", pcResponseCred?pcResponseCred:"NULL");
                        pcTicketOut = aselect_filter_get_param(pPool, pcResponseCred, "ticket=", "&", TRUE);
                        if (pcTicketOut != NULL) {
                            // Save Uid
                            if ((pcUIDOut = aselect_filter_get_param(pPool, pcResponseCred, "uid=", "&", TRUE))) {
                                if ((pcOrganizationOut = aselect_filter_get_param(pPool, pcResponseCred, "organization=", "&", TRUE))) {
                                    pcTmp = aselect_filter_get_param(pPool, pcResponseCred, "usi=", "&", TRUE);
                                    if (pcTmp) {
					TRACE1("passUsi=%s", pcTmp);
                                        passUsiAttribute = pcTmp;
				    }
                                    pcAttributes = aselect_filter_get_param(pPool, pcResponseCred, "attributes=", "&", TRUE);
                                    if (pcAttributes)
                                        pcAttributes = aselect_filter_base64_decode(pPool, pcAttributes);
				    if (passUsiAttribute != NULL) {
					pcAttributes = ap_psprintf(pPool, "usi=%s&%s", passUsiAttribute, pcAttributes);
				    }
                                    iAction = ASELECT_FILTER_ACTION_SET_TICKET;
                                }
                                else {
                                    TRACE1("could not find organization in response: %s", pcResponseCred);
                                    iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;
                                }
                            }
                            else {
                                TRACE1("could not find uid in response: %s", pcResponseCred);
                                iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;
                            }
                        }
                        else { // Could not find ticket in response
                            TRACE1("could not find ticket in response: %s", pcResponseCred);
                            iError = ASELECT_FILTER_ERROR_AGENT_RESPONSE;
                        }
                    }
                    else {
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
                else {
                    iError = ASELECT_FILTER_ERROR_AGENT_NO_RESPONSE;
                }
            }
            else { // Could not find a RID, authenticate user
                iAction = ASELECT_FILTER_ACTION_AUTH_USER;
            }
        }
        else { // No Credentials present, authenticate user
            iAction = ASELECT_FILTER_ACTION_AUTH_USER;
        }
    }
    TRACE3("==== 3. Action iError=%d iAction=%s, iRet=%s", iError, filter_action_text(iAction), filter_return_text(iRet));

    //
    // If we do not have an error then act according to iAction
    //
    if (iError == ASELECT_FILTER_ERROR_OK) {
        // Act according to action
        switch(iAction) {
            case ASELECT_FILTER_ACTION_ACCESS_GRANTED:
                // User was granted access
                // Check for known requests such as show_aselect_bar and kill_ticket
                TRACE1("Action: ASELECT_FILTER_ACTION_ACCESS_GRANTED, args=%s", pRequest->args);
                if (pRequest->args) {
                    pcRequest = aselect_filter_get_param(pPool, pRequest->args, "request=", "&", TRUE);
                    if (pcRequest) {
			TRACE1("pcRequest=%s", pcRequest);
                        if (strstr(pcRequest, "aselect_show_bar") && pConfig->bUseASelectBar) {
                            // Return the frame around the logout_bar and the application
			    //Old needs 'aselect_app_url' to pass app parameters
                            //if ((pcASelectAppURL = aselect_filter_get_param(pPool, pRequest->args, "aselect_app_url=", "&", TRUE))) 
			    //	aselect_filter_removeUnwantedCharacters(pcASelectAppURL);
			    //end Old
			    if (securedAselectAppArgs != NULL)
                                iRet = aselect_filter_show_barhtml(pPool, pRequest, pConfig, securedAselectAppArgs);
                            else
                                iRet = aselect_filter_show_barhtml(pPool, pRequest, pConfig, pConfig->pCurrentApp->pcLocation);
			    // iRet is now set to DONE
                        }
                        else if (strstr(pcRequest, "aselect_generate_bar")) {
                            // Return the logout_bar content, containing the logout button
			    char *pcLogoutHTML = pConfig->pcLogoutTemplate;  // configurable logout template

			    TRACE1("aselect_generate_bar, logout loc=%s", pConfig->pCurrentApp->pcLocation);
                            pRequest->content_type = "text/html";
                            ap_send_http_header(pRequest);

			    // Bauke 20080928: added configurable Logout Bar
			    while (pcLogoutHTML && (strstr(pcLogoutHTML, "[action]") != NULL)) {
				pcLogoutHTML = aselect_filter_replace_tag(pPool, "[action]", pConfig->pCurrentApp->pcLocation, pcLogoutHTML);
			    }
			    ap_rprintf(pRequest, "%s\n", (pcLogoutHTML)? pcLogoutHTML: "");
                            iRet = DONE;
                        }
                        else if (strstr(pcRequest, "aselect_kill_ticket")) {
                            // Kill the user ticket
                            if ((pcTicket = aselect_filter_get_cookie(pPool, headers_in, "aselectticket="))) {
                                if ((pcResponseKill = aselect_filter_kill_ticket(pRequest, pPool, pConfig, pcTicket, &timer_data))) {
				    iError = aselect_filter_get_error(pPool, pcResponseKill);

				    if (iError == ASELECT_FILTER_ASAGENT_ERROR_OK) {
					// Successfully killed the ticket, now redirect to the aselect-server
					if ((pcASelectServerURL = aselect_filter_get_cookie(pPool, headers_in, "aselectserverurl=")))
					{
					    TRACE("Delete cookies");
					    pRequest->content_type = "text/html";
					    pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s;%s", "aselectticket", pConfig->pCurrentApp->pcLocation, addedSecurity);
					    ap_table_add(headers_out, "Set-Cookie", pcCookie);
					    TRACE1("Set-Cookie: %s", pcCookie);
					    pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s;%s", "aselectuid", pConfig->pCurrentApp->pcLocation, addedSecurity);
					    ap_table_add(headers_out, "Set-Cookie", pcCookie);
					    TRACE1("Set-Cookie: %s", pcCookie);
					    pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s;%s", "aselectorganization", pConfig->pCurrentApp->pcLocation, addedSecurity);
					    ap_table_add(headers_out, "Set-Cookie", pcCookie);
					    TRACE1("Set-Cookie: %s", pcCookie);
					    pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s;%s", "aselectserverurl", pConfig->pCurrentApp->pcLocation, addedSecurity);
					    ap_table_add(headers_out, "Set-Cookie", pcCookie);
					    TRACE1("Set-Cookie: %s", pcCookie);
					    if (/*pConfig->bUseCookie ||*/ strchr(pConfig->pcPassAttributes,'c')!=0) {  // Bauke: added
						pcCookie = ap_psprintf(pPool, "%s=; version=1; max-age=0; path=%s;%s", "aselectattributes", pConfig->pCurrentApp->pcLocation, addedSecurity);
						ap_table_add(headers_out, "Set-Cookie", pcCookie);
						TRACE1("Set-Cookie: %s", pcCookie);
					    }
					    // else: no aselectattributes cookie needed

					    ap_send_http_header(pRequest);
					    ap_rprintf(pRequest, ASELECT_FILTER_CLIENT_REDIRECT, pcASelectServerURL, pcASelectServerURL);
					    iRet = DONE;
                                        }
                                        else {
                                            iError = ASELECT_FILTER_ERROR_NO_SUCH_COOKIE;
                                            TRACE1("aselect_filter_get_cookie(aselectserverurl) FAILED: %d", iError);
                                            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, pRequest,
                                                ap_psprintf(pPool, "ASELECT_FILTER:: aselect_filter_get_cookie(aselectserverurl) FAILED: %d", iError));
                                        }
                                    }
                                    else {
                                        TRACE1("aselect_filter_kill_ticket FAILED: %d", iError);
                                        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, pRequest,
                                            ap_psprintf(pPool, "ASELECT_FILTER:: aselect_filter_kill_ticket FAILED: %d", iError));
                                    }
                                }
                                else {
                                    iError = ASELECT_FILTER_ERROR_INTERNAL;
                                    TRACE1("aselect_filter_kill_ticket FAILED: %d", iError);
                                    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, pRequest,
                                        ap_psprintf(pPool, "ASELECT_FILTER:: aselect_filter_kill_ticket FAILED: %d", iError));
                                }
                            }
                            else { // Could not find ticket to kill
                                iError = ASELECT_FILTER_ERROR_NO_SUCH_COOKIE;
                                TRACE1("aselect_filter_get_cookie(aselectticket) FAILED: %d", iError);
                                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, pRequest,
                                    ap_psprintf(pPool, "ASELECT_FILTER:: aselect_filter_get_cookie(aselectticket) FAILED: %d", iError));
                            }
                        }
                        else { // Nothing interesting in the request=param, so continue as normal
			    TRACE("No recognized request given");
                            iRet = DECLINED;
                        }
                    }
                    else { // No arguments we are interested in, so continue as normal
			TRACE("No request given");
                        iRet = DECLINED;
                    }
                }
                else {
		    TRACE("No arguments given");
                    iRet = DECLINED;
                }
		break;

            case ASELECT_FILTER_ACTION_AUTH_USER:
                // User does not have a valid CREDENTIALS and must be authenticated by the ASelect Server
                // Contact ASelect Agent to find the users ASelect Server

                TRACE("Action: ASELECT_FILTER_ACTION_AUTH_USER");
                TRACE2("iRedirectMode: %d redirectURL=%s", pConfig->iRedirectMode, pConfig->pCurrentApp->pcRedirectURL);
                if (*pConfig->pCurrentApp->pcRedirectURL) {
                    TRACE1("Using fixed app_url: %s", pConfig->pCurrentApp->pcRedirectURL);
                    if (pRequest->args != NULL) {
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
                else {
                  if (pConfig->iRedirectMode == ASELECT_FILTER_REDIRECT_FULL) {
                      if (pRequest->args != NULL) {
                          pcUrl = ap_psprintf(pPool, "%s?%s", pRequest->uri, pRequest->args);
                          pcAppUrl = ap_construct_url(pPool, pcUrl, pRequest);
                      }
                      else
                          pcAppUrl = ap_construct_url(pPool, pRequest->uri, pRequest);
                  }
                  else
                      pcAppUrl = ap_construct_url(pPool, pConfig->pCurrentApp->pcLocation, pRequest);
                }
                
		// Remove: request=aselect_show_bar if present, otherwise we would get 2 of them
		if (pConfig->bUseASelectBar) {
		    char *req = "request=aselect_show_bar";
		    char *p = strstr(pcAppUrl, req);
		    int len = strlen(req);
		    if (p) {
			TRACE1("Removed: %s", req);
			if (p > pcAppUrl && *(p-1) == '&') {
			    p--; len++;
			}
			pcAppUrl = ap_psprintf(pPool, "%.*s%s", p-pcAppUrl, pcAppUrl, p+len);
		    }
		}
                TRACE1("Redirect for authentication to app_url: %s", pcAppUrl);
                if ((pcResponseAU = aselect_filter_auth_user(pRequest, pPool, pConfig, pcAppUrl, &timer_data))) {
                    iError = aselect_filter_get_error(pPool, pcResponseAU);
                }

                if (iError == ASELECT_FILTER_ASAGENT_ERROR_OK) {
                    TRACE1("response: %s", pcResponseAU);
                    //
                    // build the redirection URL from the response
                    //
                    if ((pcRID = aselect_filter_get_param(pPool, pcResponseAU, "rid=", "&", TRUE))) {
                        if ((pcASelectServer = aselect_filter_get_param(pPool, pcResponseAU, "a-select-server=", "&", TRUE))) {
                            if ((pcASUrl = aselect_filter_get_param(pPool, pcResponseAU, "as_url=", "&", TRUE))) {
                                iRet = aselect_filter_gen_top_redirect(pPool, addedSecurity, pRequest, pcASUrl, pcASelectServer, pcRID);
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
                        ap_psprintf(pPool, "ASELECT_FILTER:: aselect_filter_auth_user FAILED (%d)", iError));
                }
                break;

            case ASELECT_FILTER_ACTION_SET_TICKET:
                //
                // Generate & set A-Select cookies
                //
                TRACE3("Action: ASELECT_FILTER_ACTION_SET_TICKET: %s - %s - %s", pcTicketOut, pcUIDOut, pcOrganizationOut);
		if (/*pConfig->bUseCookie ||*/ strchr(pConfig->pcPassAttributes,'c')!=0) {  // Bauke: added
		    // Pass attributes in a cookie
		    pcCookie4 = ap_psprintf(pPool, "%s=%s; version=1; path=%s;%s", "aselectattributes", 
			    (pcAttributes == NULL) ? "" : pcAttributes, pConfig->pCurrentApp->pcLocation, addedSecurity);
		    TRACE1("Set-Cookie: %s", pcCookie4);
		    ap_table_add(headers_out, "Set-Cookie", pcCookie4); 
		}
		if (/*!pConfig->bUseCookie ||*/ strchr(pConfig->pcPassAttributes,'q')!=0 ||
			    strchr(pConfig->pcPassAttributes,'h')!=0 || strchr(pConfig->pcPassAttributes,'t')!=0) {  // Bauke: added
		    // Pass attributes in the html header and/or query string
		    iError = aselect_filter_passAttributesInUrl(iError, pcAttributes, pPool, pRequest, pConfig,
				    pcTicketOut, pcUIDOut, pcOrganizationOut, pcRequestLanguage, headers_in, &timer_data);
		}

                pcCookie = ap_psprintf(pPool, "%s=%s; version=1; path=%s;%s", "aselectticket", pcTicketOut, pConfig->pCurrentApp->pcLocation, addedSecurity);
                TRACE1("Set-Cookie: %s", pcCookie);
                ap_table_add(headers_out, "Set-Cookie", pcCookie); 

                pcCookie2 = ap_psprintf(pPool, "%s=%s; version=1; path=%s;%s", "aselectuid", pcUIDOut, pConfig->pCurrentApp->pcLocation, addedSecurity);
                TRACE1("Set-Cookie: %s", pcCookie2);
                ap_table_add(headers_out, "Set-Cookie", pcCookie2); 

                pcCookie3 = ap_psprintf(pPool, "%s=%s; version=1; path=%s;%s", "aselectorganization", pcOrganizationOut, pConfig->pCurrentApp->pcLocation, addedSecurity);
                TRACE1("Set-Cookie: %s", pcCookie3);
                ap_table_add(headers_out, "Set-Cookie", pcCookie3); 

		// Filter out application parameters
                TRACE2("SecureUrl=%d RequestArgs: '%s'", pConfig->bSecureUrl, pRequest->args);
		pRequest->args = extractApplicationParameters(pPool, pRequest->args);
                TRACE1("Ticket SET --> pRequest->args='%s'",pRequest->args);
                                                                         
                iRet = aselect_filter_gen_authcomplete_redirect(pPool, pRequest, pConfig);
		// always returns DONE
                break;

            case ASELECT_FILTER_ACTION_ACCESS_DENIED:
                TRACE("Action: ACCESS_DENIED");
		break;

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
    TRACE3("==== 4. Attributes iError=%d iAction=%s, iRet=%s", iError, filter_action_text(iAction), filter_return_text(iRet));
    // Bauke, 20100520, added: iRet != DONE
    if (iRet != DONE && iError == ASELECT_FILTER_ERROR_OK && iAction == ASELECT_FILTER_ACTION_ACCESS_GRANTED) { /*!pConfig->bUseCookie ||*/
	if (strchr(pConfig->pcPassAttributes,'q')!=0 || strchr(pConfig->pcPassAttributes,'h')!=0 || strchr(pConfig->pcPassAttributes,'t')!=0) {
	    iError = aselect_filter_passAttributesInUrl(iError, pcAttributes, pPool, pRequest, pConfig, pcTicketIn, pcUIDIn, pcOrganizationIn, pcRequestLanguage, headers_in, &timer_data);
	}
	//iRet = DONE;
    }

    TRACE4("==== 5. Finish iError=%d iAction=%s, iRet=%s, bs=%d", iError, filter_action_text(iAction),
		    filter_return_text(iRet),pConfig->iBatchSize);

finish_filter_handler:
    // FINISH TIMER
    ok = (iRet == DONE || iAction == ASELECT_FILTER_ACTION_ACCESS_GRANTED);
    if (pConfig && pConfig->pCurrentApp) {
	char *pData, buf[1000], *pcResponse;
	int rc;
	timer_finish(&timer_data);
	pData = timer_pack(pPool, &timer_data, "flt_all", pConfig->pCurrentApp->pcAppId, ok);
	if (pConfig->iBatchSize > 0 && pConfig->iSensorPort > 0 && *pConfig->pcSensorIP) {
	    sprintf(buf, "GET /?request=store&data=%s HTTP/1.1\r\n", pData);
	    pcResponse = aselect_filter_send_request(pRequest->server, pPool, pConfig->pcSensorIP, pConfig->iSensorPort,
					buf, strlen(buf), NULL, 0);
	    if (!pcResponse) {  // disable connection
		// Does not work however, the worker is killed!
		pConfig->iSensorPort = 0;
		TRACE("Disable LbSensor");
	    }
	}
	else
	    TRACE1("Sensor data [%s] not sent", pData);
    }
    TRACE4("==== 6. Returning %s, ok=%d %s ? %s", filter_return_text(iRet), ok, pRequest->uri, pRequest->args);
    TRACE("---- }\n====");

    // Cleanup
    if (pPool != NULL)
        ap_destroy_pool(pPool);

    return iRet;
}

//
// Bauke added: Pass attributes in the query string and/or in the header
//
static int aselect_filter_passAttributesInUrl(int iError, char *pcAttributes, pool *pPool, request_rec *pRequest,
	    PASELECT_FILTER_CONFIG pConfig, char *pcTicketIn, char *pcUIDIn, char *pcOrganizationIn,
	    char *pcRequestLanguage, table *headers_in, TIMER_DATA *pt)
{
    TRACE4("passAttributesinUrl iError=%d, TicketIn=%s, UidIn=%s, OrgIn=%s", iError,
		pcTicketIn?pcTicketIn:"NULL", pcUIDIn?pcUIDIn:"NULL", pcOrganizationIn?pcOrganizationIn:"NULL");
    if (pcAttributes == NULL) {
	int i, purge, stop, try;
	char *pcResponse, *newArgs;

	TRACE("Get Attributes");
	pcResponse = aselect_filter_attributes(pRequest, pPool, pConfig, pcTicketIn, pcUIDIn, pcOrganizationIn, pt);
	if (pcResponse) {
	    TRACE1("Attributes Response [%.40s]", pcResponse);
	    iError = aselect_filter_get_error(pPool, pcResponse);

	    if (iError == ASELECT_FILTER_ASAGENT_ERROR_OK) {
		newArgs = "";  // Start with no args at all
		pcAttributes = aselect_filter_get_param(pPool, pcResponse, "attributes=", "&", TRUE);
		if (pcAttributes) {
		    pcAttributes = aselect_filter_base64_decode(pPool, pcAttributes);

		    TRACE2("Start: SecureUrl=%d pRequestArgs=%s", pConfig->bSecureUrl, (pRequest->args)? pRequest->args: "NULL");
		    TRACE1("Attributes from Agent: %s", pcAttributes);
		    // Filter out unwanted characters in the URL
		    if (pConfig->bSecureUrl && pRequest->args) {
		    	aselect_filter_removeUnwantedCharacters(pRequest->args);
		    }
		    TRACE2("End: %s, AttrCount=%d", (pRequest->args)? pRequest->args: "NULL", pConfig->iAttrCount);

		    // Perform attribute filtering!
		    // First handle the special Saml attribute token (if present)
		    if (strchr(pConfig->pcPassAttributes,'t')!=0) {  // Pass Saml token in header
			char *p, *q, hdrName[60];
			int i, len, save;

			p = aselect_filter_get_param(pPool, pcAttributes, "saml_attribute_token=", "&", TRUE/*UrlDecode*/);
			TRACE1("token=%.100s", p);
			// We have a base64 encoded Saml token, pass it in a custom header
			// Note the minus signs in the header name instead of underscores
			len = (p)? strlen(p): 0;
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
		    // Three fields separted by a comma: <condition>,<ldap_name>,<attribute_name>
		    // If <condition> is empty or it evaluates to 'true' the header is written,
		    // otherwise it's not.
		    // <ldap_name> can be an expression (it must be enclosed by single quotes)
		    // <condition> and <ldap_name> can contain attribute expressions [attr,...]
		    //
		    for (i = 0; i < pConfig->iAttrCount; i++) {
			char *p, *q;
			char condName[400], ldapName[400], attrName[200], buf[600];
			int constant;

			TRACE2("attribute_check:: %d: %s", i, pConfig->pAttrFilter[i]);
			splitAttrFilter(pConfig->pAttrFilter[i], condName, sizeof(condName),
				    ldapName, sizeof(ldapName), attrName, sizeof(attrName));

			if (attrName[0] == '\0')  // no HTTP header name
			    continue;
			//TRACE3("Attr[%s|%s|%s]", condName, ldapName, attrName);

			// Check condition
			if (!conditionIsTrue(pPool, pcAttributes, condName)) {
			    TRACE("Do NOT include header");
			    continue;
			}

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
				p = aselect_filter_get_param(pPool, pcAttributes, buf, "&", TRUE/*urlDecode*/); // was FALSE
			    }
			}
			// 20111204: no more
			//if (!constant && !(p && *p) && digidName[0] != '\0') {  // try to use DigiD value
			//    sprintf(buf, "digid_%s=", digidName);
			//    p = aselect_filter_get_param(pPool, pcAttributes, buf, "&", FALSE);
			//}
			if (strcmp(attrName, "language")==0 && pcRequestLanguage != NULL) {
			    p = pcRequestLanguage; // replace attribute value
			    constant = 0;
			}
			if (p && (*p||constant)) {
			    char *encoded, *decoded;

			    // p points to the attribute value
			    TRACE1("attribute_check:: value=%s", p);
			    if (constant) {
				p = replaceAttributeValues(pPool, pcAttributes, p, TRUE/*urlDecode*/); // was FALSE
			    }
			    TRACE1("attribute_check:: value=%s", p);
			    if (strcmp(attrName, "AuthHeader") != 0) { // 20111128
				// Only for passing parameters in the URL parameters
				TRACE1("url_encode :: value=%s", p);
				p = aselect_filter_url_encode(pPool, p); // 20111206
				TRACE1("url_encoded:: value=%s", p);
				if (newArgs[0])
				    newArgs = ap_psprintf(pPool, "%s&%s=%s", newArgs, attrName, p);
				else
				    newArgs = ap_psprintf(pPool, "%s=%s", attrName, p);
			    }
			    TRACE1("attribute_check:: newArgs=%s", newArgs);

			    // 20111206: p is no longer url encoded
			    if (strcmp(attrName, "AuthHeader") == 0) {
				decoded = ap_psprintf(pPool, "%s:", p);  // <username>:<password>
				//aselect_filter_url_decode(decoded); // 20111206
				encoded = aselect_filter_base64_encode(pPool, decoded);
				ap_table_set(headers_in, "Authorization", ap_psprintf(pPool, "Basic %s", encoded));
			    }
			    else if (strchr(pConfig->pcPassAttributes,'h')!=0) { // Pass in the header
				//TRACE2("X-Header - %s: %s", attrName, p);
				//decoded = ap_pstrdup(pPool, p); //20111206
				//aselect_filter_url_decode(decoded); //20111206
				ap_table_set(headers_in, ap_psprintf(pPool, "X-%s", attrName), p);  // 20111206 decoded);
			    }
			    TRACE1("attribute_check:: purge=%s", pRequest->args);

			    // A value for 'attrname' was added
			    // Remove the same attribute from the original attributes (if present), can occur more than once
			    for (purge=1; purge; ) {
				purge = 0;
				for (p = pRequest->args; p != NULL; p = q+1) {
				    q = strstr(p, attrName);
				    if (!q)
					break;
				    // Example args: my_uid=9876&uid2=0000&uid=1234&uid=9876
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
			//TRACE3("New arguments [%d]: %s, req=%s", i, newArgs, pRequest->args);
		    }
		}
		else {
		    TRACE("No attributes in response");
		    //pRequest->args = "";
		}
		TRACE1("PassAttributes=%s", pConfig->pcPassAttributes);
		if (strchr(pConfig->pcPassAttributes,'q')!=0) {
		    // Add the new args in front of the original ones, newArgs contains URL encoded values (20111206)
		    if (pRequest->args && pRequest->args[0])
			pRequest->args = ap_psprintf(pPool, "%s&%s", newArgs, pRequest->args);
		    else
			pRequest->args = newArgs;
		    // If we want to do this, do-not encode the = and & signs!!!
		    //pRequest->args = aselect_filter_url_encode(pPool, pRequest->args); // no longer needed 20111206
		}
		TRACE2("Args modified to [%s], passed in: %s", pRequest->args, pConfig->pcPassAttributes);
	    }
	    else iError = ASELECT_FILTER_ERROR_FAILED;
	}
	else iError = ASELECT_FILTER_ERROR_AGENT_NO_RESPONSE;
    }
    return iError;
}

//
// Split 'aselect_filter_add_attribute' value in three
//
static void splitAttrFilter(char *attrFilter, char *condName, int condLen,
		char *ldapName, int ldapLen, char *attrName, int attrLen)
{
    char *p, *q, buf[40];
    int len, i;

    p = attrFilter;
    if (condName) condName[0] = '\0';
    if (ldapName) ldapName[0] = '\0';
    if (attrName) attrName[0] = '\0';

    if (*p == ',')  // empty condName
	q = p;
    else {  // parse condition
	q = strchr(p, '(');  // e.g. contains(
	if (q) {
	    sprintf(buf, ")%.*s", q-p, p);
	    q = strstr(p, buf);  // e.g. )contains
	    if (q) 
		q = strchr(q, ',');
	    else
		TRACE2("No match '%s' found from: %s", buf, p);
	}
	if (!q) {
	    q = strchr(p, ',');
	}
    }
    if (!q)  // condName
	return;

    if (condName) {
	len = (q-p < condLen)? q-p: condLen-1;
	strncpy(condName, p, len);
	condName[len] = '\0';
    }
    p = q+1;
    // p points to start of <ldap_name>
    q = strrchr(p, ',');  // 20111128: find last comma
    if (!q)  // ldapName
	return;
    if (ldapName) {
	len = (q-p < ldapLen)? q-p: ldapLen-1;
	strncpy(ldapName, p, len);
	ldapName[len] = '\0';
    }
    p = q+1;
    for (q=p; *q; q++)
	;

    //attrName
    if (attrName) {
	len = (q-p < attrLen)? q-p: attrLen-1;
	strncpy(attrName, p, len);
	attrName[len] = '\0';
    }
}

//
// Replace in 'text' all occurrences of [attr,<attr_name>]
// by the value of attribute <attr_name>
// If something goes wrong no replacement (or partial replacement) takes place
//
static char *replaceAttributeValues(pool *pPool, char *pcAttributes, char *text, int bUrlDecode)
{
    // cn=[attr,uid],org=o transforms into cn=33400056,org=o
    char *newValue = text;
    char *begin, *end, *val, buf[120];

    if (!text)
	return NULL;

    begin = strstr(newValue, "[attr,");
    for ( ; begin != NULL; begin = strstr(newValue, "[attr,")) {
	end = strchr(begin, ']');
	if (end == NULL) {// syntax error
	    TRACE1("Attribute, no matching ] from: %.20s...", begin);
	    break;
	}
	sprintf(buf, "%.*s=", end-(begin+6), begin+6);
	val = aselect_filter_get_param(pPool, pcAttributes, buf, "&", bUrlDecode);
	// substitute some
	if (val == NULL) {  // no real value has been set
	    TRACE2("Parameter '%.*s' not found", strlen(buf)-1, buf);
	    val = "";
	}
	//TRACE3("Replace attribute '%.*s' by '%s'", strlen(buf)-1, buf, val);
	newValue = ap_psprintf(pPool, "%.*s%s%s", begin-newValue, newValue, val, end+1);
    }
    return newValue;
}

//
// Replace function by the string "true" of "false"
// Looks like: <beginToken>value1<septoken>value2<endToken>
//             begin       arg1  end1      arg2  end2      pend
//
static char *evaluateFunction(pool *pPool, char *condValue, char *funcName)
{
    char *p, *begin, *arg1, *arg2, *end1, *end2, *pend;
    char beginToken[40], endToken[40], *sepToken = "[~]";
    char *substValue, *fun;
    int finalLen, len, not;

    if (!condValue)
	return NULL;
    sprintf(beginToken, "%s(", funcName);
    sprintf(endToken, ")%s", funcName);

    fun = funcName;
    not = (strncmp(funcName, "not_", 4) == 0)? 1: 0;
    if (not) funcName += 4;

    p = strstr(condValue, beginToken);
    for ( ; p != NULL; ) {
	end1 = arg2 = end2 = pend = NULL;
	begin = p;
	//TRACE1("evaluate=[%s]", begin);
	arg1 = begin + strlen(beginToken);
	end1 = strstr(arg1, sepToken);
	if (end1) arg2 = end1 + strlen(sepToken);
	if (arg2) end2 = strstr(arg2, endToken);
	if (end2) pend = end2 + strlen(endToken);
	//TRACE5("function=%s arg1=[%.*s] arg2=[%.*s]", fun, end1-arg1, arg1, end2-arg2, arg2);
	if (!(end1 && arg2 && end2)) {
	    // must replace something to prevent loops
	    TRACE1("Syntax error at: %s", begin);
	    strncpy(begin, "____________________", arg1-begin-1);  // invalidate begintoken
	    p = strstr(arg1, beginToken);
	    return NULL; // continue;
	}

	// substitute from 'begin' to 'pend', both have a value here
	substValue = "false";

	if (strcmp(funcName, "equals") == 0) {
	    if (end1-arg1 == end2-arg2 && strncmp(arg1, arg2, end1-arg1)==0)
		substValue = "true";
	}
	else if (strcmp(funcName, "contains") == 0) {
	    int sav1 = *end1;
	    int sav2 = *end2;
	    *end1 = *end2 = '\0';
	    if (strstr(arg1, arg2) != NULL)
		substValue = "true";
	    *end1 = sav1;
	    *end2 = sav2;
	}
	else if (strcmp(funcName, "and") == 0) {
	    if (end1-arg1 == 4 && strncmp(arg1, "true", 4)==0 &&
		    end2-arg2 == 4 && strncmp(arg2, "true", 4)==0)
		substValue = "true";
	}
	else if (strcmp(funcName, "or") == 0) {
	    if (end1-arg1 == 4 && strncmp(arg1, "true", 4)==0 ||
		    end2-arg2 == 4 && strncmp(arg2, "true", 4)==0)
		substValue = "true";
	}
	// negations
	if (not) {
	    if (strcmp(substValue, "true") == 0)
		substValue = "false";
	    else
		substValue = "true";
	}

	finalLen = strlen(pend);
	condValue = ap_psprintf(pPool, "%.*s%s%s", begin-condValue, condValue, substValue, pend);
	len = strlen(condValue) - finalLen;  // that's where we were
	p = strstr(condValue+len, beginToken);  // and advance
	TRACE1("evaluated=[%s]", condValue);
    }
    return condValue;  // the new value
}

// Return 1 for true, 0 for false
static int conditionIsTrue(pool *pPool, char *pcAttributes, char *condValue)
{
    if (!condValue[0])
	return 1;  // true

    // Replace all [attr,<attr_name>] constructions
    TRACE1("condition=[%s]", condValue);
    condValue = replaceAttributeValues(pPool, pcAttributes, condValue, TRUE/*urlDecode*/);
    TRACE1("replaced =[%s]", condValue);

    // Next evaluate, first contains and equals
    condValue = evaluateFunction(pPool, condValue, "not_contains");
    condValue = evaluateFunction(pPool, condValue, "contains");
    condValue = evaluateFunction(pPool, condValue, "not_equals");
    condValue = evaluateFunction(pPool, condValue, "equals");
    condValue = evaluateFunction(pPool, condValue, "not_and");
    condValue = evaluateFunction(pPool, condValue, "and");
    condValue = evaluateFunction(pPool, condValue, "not_or");
    condValue = evaluateFunction(pPool, condValue, "or");

    return (condValue!=NULL && strcmp(condValue,"true")==0)?1 : 0;
}

static char *aselect_filter_findNoCasePattern(const char *text, const char *pattern)
{
      char *pptr, *sptr, *start;

      for (start = (char *)text; *start != '\0'; start++)
      {
            /* find start of pattern in string */
            for ( ; ((*start!='\0') && (toupper(*start) != toupper(*pattern))); start++)
                  ;
            if (*start == '\0')
                  return NULL;

            pptr = (char *)pattern;
            sptr = (char *)start;
            while (toupper(*sptr) == toupper(*pptr)) {
                  sptr++;
                  pptr++;
                  /* if end of pattern then pattern was found */
                  if (*pptr == '\0')
                        return (start);
            }
      }
      return NULL;
}

static void aselect_filter_removeUnwantedCharacters(char *args)
{
    int stop, len;
    char *p, *q;

    for (stop=0 ; !stop; ) {
	len = strlen(args);
	aselect_filter_url_decode(args);
	TRACE1("Loop: %s", (args)? args: "NULL");
	if (len == strlen(args)) {
	    for (p = q = args; *q; ) {
		// 20100521, Bauke: " added to the list below
		if (*q == '%' || *q == '\r' || *q == '\n' || *q == '>' || *q == '<' || *q == '"')
		    q++;
		else
		    *p++ = *q++;
	    }
	    *p++ = '\0';
	    stop = 1;
	}
    }
    for (stop=0 ; !stop; ) {
	len = strlen(args);
	p = aselect_filter_findNoCasePattern(args, "script:");
	if (p) {
	    q = p + strlen("script:");
	    *p++ = '_';
	    for ( ; *q; ) {
		*p++ = *q++;
	    }
	    *p++ = *q++;  // null-byte too
	}
	if (len == strlen(args))
	    break;
    }
}

//
// Use to create the per server configuration data
//
/*static void *aselect_filter_create_config(pool *pPool, server_rec *pServer)
{
    PASELECT_FILTER_CONFIG  pConfig = NULL;

    TRACE("aselect_filter_create_config");
    if ((pConfig = (PASELECT_FILTER_CONFIG) ap_palloc(pPool, sizeof(ASELECT_FILTER_CONFIG))))
    {
        memset(pConfig, 0, sizeof(ASELECT_FILTER_CONFIG));
    }
    else {
	TRACE("aselect_filter_create_config::ERROR:: could not allocate memory for pConfig");
    }
    return pConfig;
}*/

static const char *aselect_filter_set_agent_address(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);

    if (!pConfig)
        return "A-Select ERROR: Internal error when setting A-Select IP";
    if (!(pConfig->pcASAIP = ap_pstrdup(parms->pool, arg)))
	return "A-Select ERROR: Internal error when setting A-Select IP";

    TRACE1("aselect_filter_set_agent_address:: ip: %s", pConfig->pcASAIP);
    return NULL;
}

static const char *
aselect_filter_set_agent_port(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    char *pcASAPort;

    if (!pConfig)
        return "A-Select ERROR: Internal error when setting A-Select port";
    if (!(pcASAPort = ap_pstrdup(parms->pool, arg)))
	return "A-Select ERROR: Internal error when setting A-Select port";

    TRACE1("aselect_filter_set_agent_port:: port: %s", pcASAPort);
    pConfig->iASAPort = atoi(pcASAPort);
    return NULL;
}

static const char *
aselect_filter_set_sensor_address(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);

    if (!pConfig)
        return "A-Select ERROR: Internal error when setting A-Select IP";
    if (!(pConfig->pcSensorIP = ap_pstrdup(parms->pool, arg)))
	return "A-Select ERROR: Internal error when setting A-Select IP";

    TRACE1("aselect_filter_set_sensor_address:: ip: %s", pConfig->pcSensorIP);
    return NULL;
}

static const char *
aselect_filter_set_sensor_port(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    char *pcPort;

    if (!pConfig)
        return "A-Select ERROR: Internal error when setting A-Select port";
    if (!(pcPort = ap_pstrdup(parms->pool, arg)))
	return "A-Select ERROR: Internal error when setting A-Select port";

    TRACE1("aselect_filter_set_sensor_port:: port: %s", pcPort);
    pConfig->iSensorPort = atoi(pcPort);
    pConfig->iBatchSize = 1;  // default, send data to LbSensor
    return NULL;
}

static const char *
aselect_filter_add_authz_rule(cmd_parms *parms, void *mconfig, const char *arg1, const char *arg2, const char *arg3)
{
    int i;
    PASELECT_APPLICATION pApp;
    PASELECT_FILTER_CONFIG  pConfig = (PASELECT_FILTER_CONFIG) 
        ap_get_module_config(parms->server->module_config, &aselect_filter_module);

    if (pConfig) {
        for (i=0; i<pConfig->iAppCount; i++) {
            if (strcmp(pConfig->pApplications[i].pcAppId, arg1) == 0)
                break;
        }
        if (i >= pConfig->iAppCount) {
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
    else {
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

    if (!pConfig) {
        return "A-Select ERROR: Internal error: missing configuration object";
    }
    if (pConfig->iAppCount >= ASELECT_FILTER_MAX_APP) {
	return "A-Select ERROR: Reached max possible application IDs";
    }
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
    if (!((pApp->pcLocation = ap_pstrdup(parms->pool, arg1)) &&
	 (pApp->pcAppId = ap_pstrdup(parms->pool, arg2)) ) ) {
	return "A-Select ERROR: Out of memory while adding applications";
    }
    if (strcmp(arg3, "none") != 0 &&
	strcmp(arg3, "default") != 0)
    {
	pcTok = arg3;
	while (*pcTok) {
	    TRACE1("Parsing application options token %s", pcTok);
	    if (strncmp(pcTok, "forced-logon", 12) == 0 ||
		strncmp(pcTok, "forced_logon", 12) == 0)
	    {
		pcTok += 12;
		pApp->bForcedLogon = 1;
	    }
	    else if (strncmp(pcTok, "disabled", 8) == 0)
	    {
		pcTok += 8;
		pApp->bEnabled = 0;
	    }
	    else if (strncmp(pcTok, "uid=", 4) == 0)
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
	    /* Bauke: added to force the AuthSP choice */
	    else if (strncmp(pcTok, "authsp=", 7) == 0)
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
	    else if (strncmp(pcTok, "language=", 9) == 0)
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
	    else if (strncmp(pcTok, "country=", 8) == 0)
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
	    else if (strncmp(pcTok, "remote_organization=", 20) == 0 ||
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
	    else if (strncmp(pcTok, "url=", 4) == 0)
	    {
	      pcTok += 4;
		if ((pcEnd = strchr(pcTok, ',')))
		    pApp->pcRedirectURL = ap_pstrndup(parms->pool, pcTok, pcEnd-pcTok);
		else
		    pApp->pcRedirectURL = ap_pstrdup(parms->pool, pcTok);
	      pcTok += strlen(pApp->pcRedirectURL);
	    }
	    else if (strncmp(pcTok, "extra_parameters=", 17) == 0 ||
		    strncmp(pcTok, "extra-parameters=", 17) == 0) {
		pcTok += 17;
		if ((pcEnd = strchr(pcTok, ',')))
		    pApp->pcExtra = ap_pstrndup(parms->pool, pcTok, pcEnd-pcTok);
		else
		    pApp->pcExtra = ap_pstrdup(parms->pool, pcTok);
		pcTok += strlen(pApp->pcExtra);
		pApp->pcExtra = ap_psprintf(parms->pool, "&%s",
		    pApp->pcExtra);
	    }
	    else { // Unknown option
		return ap_psprintf(parms->pool,
		    "A-Select ERROR: Unknown option in application %s near \"%s\"", 
		    pApp->pcAppId, pcTok);
	    }
	    if (*pcTok) {
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
    return NULL;
}

// 20091223: Bauke, added
// Allow to switch off the Secure and HttpOnly mechanism
//
static const char *aselect_filter_added_security(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);

    TRACE1("aselect_filter_added_security:: arg=%s", arg);
    if (!pConfig) {
	return "A-Select ERROR: Internal error during added_security";
	return NULL;
    }
    strcpy(pConfig->pcAddedSecurity, "");
    if (!arg || strstr(arg, "cookies") != NULL)  // It's the default as well
	strcat(pConfig->pcAddedSecurity, "c");  // add Secure & HttpOnly to cookies
    TRACE1("aselect_filter_added_security:: %s", pConfig->pcAddedSecurity);
    return NULL;
}

// 20091223: Bauke, added
// Specify the name and location of the log file (not mandatory)
//
static const char *aselect_filter_set_logfile(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    char **pAttr;

    if (!pConfig) {
	return "A-Select ERROR: Internal error when setting log_file";
    }
    // goes to stdout: ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, parms->server, "ASELECT_FILTER:: logfile set");
    pConfig->pcLogFileName = (arg)? ap_pstrdup(parms->pool, arg): NULL;
    aselect_filter_trace_logfilename(pConfig->pcLogFileName);
    TRACE1("aselect_filter_set_logfile:: %s", pConfig->pcLogFileName);
    return NULL;
}

// Bauke: added
// Read all attributes that must be passed in the HTML header from the config file
//
static const char *aselect_filter_add_attribute(cmd_parms *parms, void *mconfig, const char *arg)
{
    char **pAttr;
    PASELECT_FILTER_CONFIG pConfig;

    pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    if (!pConfig) {
	return "A-Select ERROR: Internal error when setting add_attribute";
    }
    if (pConfig->iAttrCount >= ASELECT_FILTER_MAX_ATTR) {
	return "A-Select ERROR: Reached max possible Attribute Filters";
    }
    pAttr = &pConfig->pAttrFilter[pConfig->iAttrCount];
    *pAttr = ap_pstrdup(parms->pool, arg);
    // Use Apache logging only
    TRACE2("aselect_filter_add_attribute:: [%d] %s", pConfig->iAttrCount, *pAttr);
    // Goes to stdout:
    //ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, parms->server,
     //       ap_psprintf(parms->pool, "aselect_filter_add_attribute:: [%d] %s", pConfig->iAttrCount, *pAttr));
    pConfig->iAttrCount++;
    return NULL;
}

// Bauke: 20110129: added
// Define public applications
//
static const char *aselect_filter_add_public_app(cmd_parms *parms, void *mconfig, const char *arg)
{
    char **pPublic;
    PASELECT_FILTER_CONFIG pConfig;

    pConfig = (PASELECT_FILTER_CONFIG) ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    if (!pConfig) {
	return "A-Select ERROR: Internal error when setting add_public app";
    }
    if (pConfig->iPublicAppCount >= ASELECT_FILTER_MAX_APP) {
	return "A-Select ERROR: Reached max possible Applications";
    }
    pPublic = &pConfig->pPublicApps[pConfig->iPublicAppCount];
    *pPublic = ap_pstrdup(parms->pool, arg);
    TRACE2("aselect_filter_add_public_app:: [%d] %s", pConfig->iPublicAppCount, *pPublic);
    pConfig->iPublicAppCount++;
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

static const char *aselect_filter_set_use_aselect_bar(cmd_parms *parms, void *mconfig, const char *arg)
{
    PASELECT_FILTER_CONFIG pConfig = (PASELECT_FILTER_CONFIG)
	    ap_get_module_config(parms->server->module_config, &aselect_filter_module);
    char *pcUseASelectBar;

    TRACE1("aselect_filter_set_use_aselect_bar:: arg=%s", arg);
    if (pConfig) {
	if ((pcUseASelectBar = ap_pstrdup(parms->pool, arg))) {
	    TRACE1("aselect_filter_set_use_aselect_bar:: %s", pcUseASelectBar);
	    pConfig->bUseASelectBar = FALSE;

	    if (strcasecmp(pcUseASelectBar, "1") == 0)
		pConfig->bUseASelectBar = TRUE;
	}
	else {
	    return "A-Select ERROR: Internal error when setting use_aselect_bar";
	}
    }
    else {
	return "A-Select ERROR: Internal error when setting use_aselect_bar";
    }
    return NULL;
}

// Bauke 20081108: added
// Boolean to activate URL escape sequence removal
//
static const char *aselect_filter_secure_url(cmd_parms *parms, void *mconfig, const char *arg)
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

static const char *aselect_filter_pass_attributes(cmd_parms *parms, void *mconfig, const char *arg)
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

//
// Registered cmds to call from httpd.conf
//
static const command_rec aselect_filter_cmds[] = 
{
    AP_INIT_TAKE1( "aselect_filter_set_agent_address", aselect_filter_set_agent_address, NULL, RSRC_CONF,
        "Usage aselect_filter_set_agent_address <ip or dns name of A-Select Agent>, example: aselect_filter_set_agent_address \"localhost\"" ),
    AP_INIT_TAKE1( "aselect_filter_set_agent_port", aselect_filter_set_agent_port, NULL, RSRC_CONF,
        "Usage aselect_filter_set_agent_port <port of A-Select Agent>, example: aselect_filter_set_agent_port \"1495\"" ),

    AP_INIT_TAKE3( "aselect_filter_add_secure_app", aselect_filter_add_secure_app, NULL, RSRC_CONF,
        "Usage aselect_filter_add_secure_app <location> <application id> <flags>, example: aselect_filter_add_secure_app \"///secure///\" \"app1\" \"forced-logon\"" ),
    AP_INIT_TAKE3( "aselect_filter_add_authz_rule", aselect_filter_add_authz_rule, NULL, RSRC_CONF,
        "Usage aselect_filter_add_authz_rule <application id> <target uri> <condition>, example: aselect_filter_add_authz_rule \"app1\" \"*\" \"role=student\"" ),

    AP_INIT_TAKE1( "aselect_filter_set_html_error_template", aselect_filter_set_html_error_template, NULL, RSRC_CONF,
        "Usage aselect_filter_set_html_error_template <path to template html page>, example: aselect_filter_set_html_error_template \"///usr//local//apache//aselect//error.html\"" ),
    AP_INIT_TAKE1( "aselect_filter_set_html_logout_template", aselect_filter_set_html_logout_template, NULL, RSRC_CONF,
        "Usage aselect_filter_set_html_logout_template <path to template html page>, example: aselect_filter_set_html_logout_template \"///usr//local//apache//aselect//logout.html\"" ),

    AP_INIT_TAKE1( "aselect_filter_set_use_aselect_bar", aselect_filter_set_use_aselect_bar, NULL, RSRC_CONF,
        "Usage aselect_filter_set_use_aselect_bar <on or off>, example: aselect_filter_set_use_aselect_bar on" ),
    AP_INIT_TAKE1("aselect_filter_set_redirect_mode", aselect_filter_set_redirection_mode, NULL, RSRC_CONF,
        "Usage aselect_filter_redirect_mode <app | full>, example: aselect_filter_redirect_mode \"app\""),

// Bauke: added entries
    AP_INIT_TAKE1("aselect_filter_secure_url", aselect_filter_secure_url, NULL, RSRC_CONF,
        "Usage: aselect_filter_secure_url < 0 | 1 >, example: aselect_filter_secure_url \"1\""),

    AP_INIT_TAKE1("aselect_filter_pass_attributes", aselect_filter_pass_attributes, NULL, RSRC_CONF,
        "Usage: aselect_filter_pass_attributes < c | q | h >, example: aselect_filter_pass_attributes \"ch\"" ),

    AP_INIT_TAKE1("aselect_filter_add_attribute", aselect_filter_add_attribute, NULL, RSRC_CONF,
        "Usage: aselect_filter_add_attribute < 0 | 1 >, example: aselect_filter_add_attribute \"0\""),

    AP_INIT_TAKE1("aselect_filter_add_public_app", aselect_filter_add_public_app, NULL, RSRC_CONF,
        "Usage: aselect_filter_add_public_app < app_url >, example: aselect_filter_add_public_app \"/website\""),

    AP_INIT_TAKE1("aselect_filter_added_security", aselect_filter_added_security, NULL, RSRC_CONF,
        "Usage: aselect_filter_added_security < cookies | >, example: aselect_filter_added_security \"cookies\"" ),

    AP_INIT_TAKE1("aselect_filter_set_logfile", aselect_filter_set_logfile, NULL, RSRC_CONF,
        "Usage: aselect_filter_set_logfile <filename>, example: aselect_filter_set_logfile \"/tmp/aselect_filter.log\""),

    AP_INIT_TAKE1( "aselect_filter_set_sensor_address", aselect_filter_set_sensor_address, NULL, RSRC_CONF,
        "Usage aselect_filter_set_sensor_address <ip or dns name of a Sensor process>, example: aselect_filter_set_sensor_address \"localhost\"" ),

    AP_INIT_TAKE1( "aselect_filter_set_sensor_port", aselect_filter_set_sensor_port, NULL, RSRC_CONF,
        "Usage aselect_filter_set_sensor_port <port of a Sensor process>, example: aselect_filter_set_sensor_port \"1805\"" ),

    { NULL }
};

// Called before logfile can be set, therefore use ap_log_error()
void *aselect_filter_create_server_config( apr_pool_t *pPool, server_rec *pServer )
{
    PASELECT_FILTER_CONFIG  pConfig = NULL;

    // Logs on stdout
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, pServer, "aselect_filter_create_server_config");
    pConfig = (PASELECT_FILTER_CONFIG) apr_palloc(pPool, sizeof(ASELECT_FILTER_CONFIG));
    if (!pConfig) {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, pServer,
	    "aselect_filter_create_server_config::ERROR:: could not allocate memory for pConfig");
        return NULL;
    }
    memset( pConfig, 0, sizeof( ASELECT_FILTER_CONFIG ) );
    return pConfig;
}

// Called before logfile can be set
void aselect_filter_register_hooks(apr_pool_t *p)
{
    //TRACE("aselect_filter_register_hooks");
    ap_hook_post_config( aselect_filter_init, NULL, NULL, APR_HOOK_MIDDLE );
    ap_hook_access_checker( aselect_filter_handler, NULL, NULL, APR_HOOK_MIDDLE );
}

module AP_MODULE_DECLARE_DATA aselect_filter_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                   // per-directory config creator
    NULL,                   // dir config merger
    aselect_filter_create_server_config,    // server config creator
    NULL,                   // server config merger
    aselect_filter_cmds,            // command table
    aselect_filter_register_hooks,      //  set up other request processing hooks
};
