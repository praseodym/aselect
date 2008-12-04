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
 * Marked Parts:
 * Author: Bauke Hiemstra - www.anoigo.nl
 *
 */

/* asf_common.h
 *
 * Functions and defines shared by the Apache 1.3 and 2.0 filters.
 *
 */


#ifndef __ASELECT_FILTER_COMMON_H
#define __ASELECT_FILTER_COMMON_H

/*
 * Apache 1.3 <--> 2.0 defines
 */
#if !defined(APACHE_13_ASELECT_FILTER) && !defined(APACHE_20_ASELECT_FILTER)
#error "APACHE_xx_ASELECT_FILTER not defined"
#endif

#include <fnmatch.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "httpd.h"
#include "http_main.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"

#ifdef APACHE_20_ASELECT_FILTER
#include <netdb.h>
#include "apr_strings.h"
#include "apr_compat.h"
#include "apr_sha1.h"
#else
#include "ap_sha1.h"
#endif


/*
 * Apache 2.0 <--> 1.3 compatibility defs (see also apr_compat.h)
 */
#ifdef APACHE_20_ASELECT_FILTER

typedef apr_pool_t      pool;
typedef apr_table_t     table;

#define FORBIDDEN                   HTTP_UNAUTHORIZED
#define AP_SHA1_CTX                 apr_sha1_ctx_t
#define SHA_DIGESTSIZE              APR_SHA1_DIGESTSIZE

#define ap_log_error(a,b,c,d)       ap_log_error(a,b,0,c,d)
#define ap_log_rerror(a,b,c,d)      ap_log_rerror(a,b,0,c,d)
#define ap_send_http_header(a)      ((void)0)
#define ap_SHA1Init(a)              apr_sha1_init(a)
#define ap_SHA1Update(a,b,c)        apr_sha1_update(a,b,c)
#define ap_SHA1Final(a,b)           apr_sha1_final(a,b)

#endif

#ifndef FALSE
#define FALSE	(0)
#define TRUE	(!FALSE)
#endif

/*
 * The filter version string, don't show version number to the general public
 */
#define ASELECT_FILTER_VERSION          "A-Select Filter" 
  
/*
 * Misc. defines
 */                                                      
#define ASELECT_FILTER_MAX_MSG          1024        // Max message that can be sent through a socket
#define ASELECT_FILTER_MAX_RECV         20000       // Max size of a response from Agent
#define ASELECT_FILTER_MAX_HEADER_SIZE  7500        // Max length of a header field (should be less than 8190 (see the LimitRequestFieldsize directive))
#define ASELECT_FILTER_SOCKET_TIME_OUT  120         // Timeout used for sockets
#define ASELECT_FILTER_MAX_APP          50          // max apps this filter can protect
#define ASELECT_FILTER_MAX_ATTR          50         // Bauke: max attribute filters
#define ASELECT_FILTER_MAX_RULES_PER_APP 50         // max authz rules per application
#define ASELECT_FILTER_TRACE_FILE       "/opt/anoigo/am/aselect/log/aselect_filter.log"  // Path to trace file

/*
 * HTML template for client-side redirect. 
 * Must include two "%s", of which both are replaced by the new location
 */
#define ASELECT_FILTER_CLIENT_REDIRECT \
    "<HTML><HEAD><TITLE>" ASELECT_FILTER_VERSION " Redirect</TITLE>\n" \
    "<meta http-equiv=\"Refresh\" content=\"0;url=%s\">\n" \
    "<script language=\"JavaScript\">top.location=\"%s\";</script>\n" \
    "</HEAD><BODY></BODY></HTML>\n"

// Bauke: No longer used!!
#define ASELECT_LOGOUT_BAR \
	"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">" \
	"<html><head>" \
	"<style>" \
	".bttn {" \
	"border-style:outset;" \
	"border-color:#9999cc;" \
	"border-width:2px;" \
	"background-color:#8080ff;" \
	"text-align:center;" \
	"width:90px;" \
	"height:20px;" \
	"font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;" \
	"color:#ffffff;" \
	"font-size:11px;" \
	"}" \
	"</style>" \
	"</head>" \
	"<base target=\"_top\">" \
	"<body bgcolor=\"#ffffff\" text=\"#000000\">" \
	"<table height=\"100%%\" width=\"100%%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">" \
	"<tr>" \
	"<td valign=\"top\" align=\"left\"></td>" \
	"<td valign=\"top\" align=\"right\">" \
	"<FORM action=\"[action]\" target=\"_top\">" \
	"<INPUT Type=\"Hidden\" Name=\"request\" value=\"aselect_kill_ticket\">" \
	"<INPUT Type=\"Submit\" class=bttn value=\"Log out\">" \
	"<a href=\"http://www.aselect.org\"><img src=\"/aselectres/aselectlogotiny.gif\" border=0></a>&nbsp;&nbsp;" \
	"</FORM>" \
	"</td>" \
	"</tr>" \
	"</table>" \
	"</body>" \
	"</html>\n"

#define ASELECT_LOGOUT_BAR_FRAME \
	"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">" \
	"<html>" \
	"<head>" \
	"</head>" \
	"<frameset rows=\"40,*\" frameborder=\"1\" bordercolor=\"#effaf6\">" \
	"<frame src=\"%s?request=aselect_generate_bar\" name=\"aselect_bar_frame\" scrolling=\"No\" id=\"aselectframe\" noresize marginwidth=\"0\" marginheight=\"0\" frameborder=\"0\">" \
	"<frame src=\"%s\" name=\"aselect_app_frame\" marginwidth=\"0\" marginheight=\"0\" frameborder=\"0\">" \
	"</frameset>" \
	"</html>\n"

/*
 * Filter errors
 */
#define ASELECT_FILTER_ERROR_FAILED         -1      // General error
#define ASELECT_FILTER_ERROR_OK             0x00    // Everything ok

#define ASELECT_FILTER_ERROR_INTERNAL                   0x0901  // A basic function gave an error. This should not happen. Maybe a reboot helps.
#define ASELECT_FILTER_ERROR_MEMORY                     0x0902  // The Filter has a memory problem.
#define ASELECT_FILTER_ERROR_CONFIG                     0x0903  // A configuration error has occured. Please check the log file for more information.
#define ASELECT_FILTER_ERROR_AGENT_RESPONSE             0x0910  // The response of the agent did not contain the expected parameters, see log file for more information.
#define ASELECT_FILTER_ERROR_AGENT_NO_RESPONSE          0x0911  // The agent did not return a response
#define ASELECT_FILTER_ERROR_AGENT_COULD_NOT_SEND       0x0912  // The request could not send to the agent 
#define ASELECT_FILTER_ERROR_AGENT_COULD_NOT_CONNECT    0x0913
#define ASELECT_FILTER_ERROR_AGENT_INVALID_ADDRESS      0x0914
#define ASELECT_FILTER_ERROR_NO_SUCH_COOKIE             0x0920  // Internal code, no cookies found 
#define ASELECT_FILTER_ERROR_NO_SUCH_VARIABLE           0x0921  // Internal code, Variable not present


/*
 * A-Select Agent errors
 */
#define ASELECT_FILTER_ASAGENT_ERROR_FAILED         -1  // Returned by aselect_filter_get_error if there is no "results=" in the error string
#define ASELECT_FILTER_ASAGENT_ERROR_OK                     0x0000  // Everything ok
#define ASELECT_FILTER_ASAGENT_ERROR_INTERNAL               0x0101  // The A-Select Agent is unable to fullfil the request 
#define ASELECT_FILTER_ASAGENT_ERROR_UNKNOWN_USER           0x0102  // User has entered a UID that is unknown to the A-Select Server
#define ASELECT_FILTER_ASAGENT_ERROR_TICKET_INVALID         0x0109  // The Application Ticket not valid
#define ASELECT_FILTER_ASAGENT_ERROR_TICKET_EXPIRED         0x010a  // The Application Ticket has expired
#define ASELECT_FILTER_ASAGENT_ERROR_UNKNOWN_TICKET         0x010b  // The Application Ticket is unknown
#define ASELECT_FILTER_ASAGENT_ERROR_AS_UNREACHABLE         0x010c  // The A-Select Agent could not reach the A-Select Server
#define ASELECT_FILTER_ASAGENT_ERROR_TICKET_MAX_REACHED     0x010d  // Too much users have a ticket
#define ASELECT_FILTER_ASAGENT_ERROR_CORRUPT_ATTRIBUTES     0x010e  // User attributes are corrupted
#define ASELECT_FILTER_ASAGENT_ERROR_INVALID_REQUEST        0x0130  // Invalid request

/*
 * A-Select Server errors
 */
#define ASELECT_SERVER_ERROR_TGT_NOT_VALID      0x0004  // The credentials are invalid
#define ASELECT_SERVER_ERROR_TGT_EXPIRED        0x0005  // The credentials have expired
#define ASELECT_SERVER_ERROR_TGT_TOO_LOW        0x0006  // The credentials are only valid for lower level authentication method 
#define ASELECT_SERVER_ERROR_UNKNOWN_TGT        0x0007  // Server Ticket is invalid


/*
 * Redirect modes
 */
#define ASELECT_FILTER_REDIRECT_TO_APP  0
#define ASELECT_FILTER_REDIRECT_FULL    1


typedef struct _ASELECT_APPLICATION
{
    char *pcLocation;
    char *pcAppId;
    char *pcUid;
    char *pcAuthsp;
    char *pcLanguage;
    char *pcCountry;
    char *pcRemoteOrg;
    char *pcExtra;    
    char *pcRedirectURL;
    int bForcedLogon;
    int bEnabled;
    int iRuleCount;
    char *pConditions[ASELECT_FILTER_MAX_RULES_PER_APP];
    char *pTargets[ASELECT_FILTER_MAX_RULES_PER_APP];  
} ASELECT_APPLICATION, *PASELECT_APPLICATION;

/*
 * Per-filter configuration
 */
typedef struct _ASELECT_FILTER_CONFIG               
{
    char    *pcASAIP;
    int     iASAPort;
    char    *pcRemoteOrg;
    ASELECT_APPLICATION pApplications[ASELECT_FILTER_MAX_APP];
    PASELECT_APPLICATION pCurrentApp;
    int     iAppCount;
    char    *pcErrorTemplate;
    int     bUseASelectBar;
    int     iRedirectMode;
    int     bConfigError;
 // Bauke: added lines
    int     bSecureUrl;
    char    pcPassAttributes[10];  // can contain a combination of 'c', 'q', 'h' (cookie, query string, header)
    char    *pAttrFilter[ASELECT_FILTER_MAX_ATTR];
    int     iAttrCount;
    char    *pcLogoutTemplate;
} ASELECT_FILTER_CONFIG, *PASELECT_FILTER_CONFIG;

/*
 * used to decide what action the filter must take
 */
typedef enum _ASELECT_FILTER_ACTION     
{
    ASELECT_FILTER_ACTION_ACCESS_GRANTED = 0,
    ASELECT_FILTER_ACTION_ACCESS_DENIED,
    ASELECT_FILTER_ACTION_AUTH_USER,
    ASELECT_FILTER_ACTION_VERIFY_CREDENTIALS,
    ASELECT_FILTER_ACTION_SET_TICKET
} ASELECT_FILTER_ACTION;

/*
 * Function declarations
 */
int         aselect_filter_print_table(void * data, const char *key, const char *val);
char *      aselect_filter_hex_to_bytes(pool *pPool, char *pcString, int *ccBytes);
void        aselect_filter_bytes_to_hex(const unsigned char *pcBytes, size_t length, char *pcResult);
int         aselect_filter_get_error(pool *pPool, char *pcError);
char *      aselect_filter_replace_tag(pool *pPool, char *pcTag, char *pcValue, char *pcSource);
char *      aselect_filter_strip_param(pool *pPool, char * pcASelectServerURL );
int         aselect_filter_receive_msg(int sd, char *pcReceiveMsg, int ccReceiveMsg );
char *      aselect_filter_send_request(server_rec *pServer, pool *pPool, char *pcASAIP, int iASAPort, char *pcSendMessage, int ccSendMessage );
char *      aselect_filter_get_param(pool *pPool, char *pcArgs, char *pcParam, char * pcDelimiter, int bUrlDecode);
char *      aselect_filter_url_encode(pool *pPool, const char *pszValue);
int         aselect_filter_url_decode(char *pszValue);
void        aselect_filter_add_nocache_headers(table *headers_out);
int         aselect_filter_gen_error_page(pool *pPool, request_rec *pRequest, int iError, char *pcErrorTemplate);
int         aselect_filter_gen_authcomplete_redirect(pool *pPool, request_rec *pRequest, PASELECT_FILTER_CONFIG pConfig); 
int         aselect_filter_gen_top_redirect(pool *pPool, request_rec *pRequest, char *pcASUrl, char *pcASelectServer, char *pcRID);
int         aselect_filter_verify_directory(pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcUri);
char *      aselect_filter_get_cookie(pool *pPool, table *headers_in, char *pcAttribute );
int         aselect_filter_gen_barhtml(pool *pPool, request_rec *pRequest, PASELECT_FILTER_CONFIG pConfig, char *pcASelectAppUrl);
char *      aselect_filter_base64_decode(pool *pPool, const char *pszValue);
char *aselect_filter_base64_encode(pool *pPool, const char *pszValue);
char *filter_action_text(ASELECT_FILTER_ACTION action);

#define ASELECT_FILTER_TRACE

/*
 * Trace definitions
 */
#ifdef ASELECT_FILTER_TRACE

    void aselect_filter_trace(const char *fmt, ... );
    int aselect_filter_print_table(void * data, const char *key, const char *val);    
    void aselect_filter_trace2(const char *filename, int line, const char *fmt, ...);    
    
    #define TRACE(x)              aselect_filter_trace2(__FILE__,__LINE__,x);
    #define TRACE1(x,o1)          aselect_filter_trace2(__FILE__,__LINE__,x,o1);
    #define TRACE2(x,o1,o2)       aselect_filter_trace2(__FILE__,__LINE__,x,o1,o2);
    #define TRACE3(x,o1,o2,o3)    aselect_filter_trace2(__FILE__,__LINE__,x,o1,o2,o3);
    #define TRACE4(x,o1,o2,o3,o4) aselect_filter_trace2(__FILE__,__LINE__,x,o1,o2,o3,o4);

#else // #ifdef ASELECT_FILTER_TRACE

    #define TRACE(x)              ((void)0);
    #define TRACE1(x,o1)          ((void)0);
    #define TRACE2(x,o1,o2)       ((void)0);
    #define TRACE3(x,o1,o2,o3)    ((void)0);
    #define TRACE4(x,o1,o2,o3,o4) ((void)0);

#endif // ASELECT_FILTER_TRACE


#endif //__ASELECT_FILTER_COMMON_H
