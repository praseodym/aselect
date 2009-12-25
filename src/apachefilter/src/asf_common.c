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
 
/* asf_common.c
 *
 * Functions shared by the Apache 1.3 and 2.0 filters.
 */

/* 
 * $Id: asf_common.c,v 1.10 2006/05/01 12:37:59 remco Exp $
 * 
 * Changelog:
 * $Log: asf_common.c,v $
 * Revision 1.10  2006/05/01 12:37:59  remco
 * Fixed bug that could cause the filter to generate an incorrect query string in the authcomplete redirect url
 *
 * Revision 1.9  2006/04/14 08:15:17  jeroen
 * added license
 *
 * Revision 1.8  2006/03/01 08:56:39  remco
 * Added option "url=..." in aselect_filter_add_secure_app, which forces the A-Select Server and filter to redirect to a fixed url after a succesful authentication.
 *
 * Revision 1.7  2005/09/12 13:50:49  remco
 * Added authorization support (untested)
 *
 * Revision 1.6  2005/05/23 15:40:42  leon
 * html logout button changed in logout bar template
 *
 * Revision 1.4  2005/05/04 08:55:00  remco
 * - Added application config directive "extra="
 * - Filter now logs if incoming message from Agent is too large
 *
 * Revision 1.3  2005/05/02 09:21:15  remco
 * - Changed parsing of application options
 * - Added 3 new application options: uid, language, and country
 * - Changed internal application storage
 * - Fixed handling of errors: some errors incorrectly resulted in re-authentication. Error response is now the same as in the ISAPI filter.
 *
 * Revision 1.2  2005/04/19 14:27:57  remco
 * Resolved bug in aselect_show_bar when no arguments were present
 *
 * Revision 1.1  2005/04/13 09:44:29  remco
 * RC1 of integrated apache 1.3 & 2.0 filter
 *
 */

#include "asf_common.h"

#ifdef ASELECT_FILTER_TRACE
//
// Bauke: Added fall back when logfile cannot be created
//
// NOTE: Best to create this file in advance, the owner must be the use running the Apache filter
// During initialization "root" is running the filter, changes during operation
// TODO: The init stage logging should go to the Apache log file!
//       
static char *LogfileName = ASELECT_FILTER_TRACE_FILE;

void aselect_filter_trace_logfilename(char *filename)
{
    if (filename)
	LogfileName = filename;
}

//
// Trace function, traces the time, process id and the logstring
//
void aselect_filter_trace(const char *fmt, ...)
{
    char    *pcTime;
    time_t  t;
    FILE    *f;
    va_list vlist;
    char *fallBack;

    //chmod(LogfileName, S_IROTH | S_IWOTH);
    //chmod(LogfileName, S_IREAD | S_IWRITE);
    f = fopen(LogfileName, "a+");
    if (!f) {
    	fallBack = "/tmp/aselect_filter.log"; // fall back
	f = fopen(fallBack, "a+");
    }
    if (f) {
        time(&t);
        pcTime = ctime(&t);
        *(pcTime + strlen(pcTime) - 1) = '\0';
        fprintf(f, "%s [%d] ", pcTime, getpid());
        va_start(vlist, fmt);
        vfprintf(f, fmt, vlist);
        va_end(vlist);
        putc('\n', f);
        fflush(f);
        fclose(f);
    }
}

void aselect_filter_trace2(const char *filename, int line, const char *fmt, ...)
{
    char    *pcTime;
    time_t  t;
    FILE    *f;
    va_list vlist;
    char *fallBack;

    //chmod(LogfileName, S_IROTH | S_IWOTH);
    f = fopen(LogfileName, "a+");
    if (!f) {
    	fallBack = "/tmp/aselect_filter.log";
	f = fopen(fallBack, "a+");
    }
    if (f) {
        time(&t);
        pcTime = ctime(&t);
        *(pcTime + strlen(pcTime) - 1) = '\0';
        fprintf(f, "%s [%s:%d / %d] ", pcTime, filename, line, getpid());
        va_start(vlist, fmt);
        vfprintf(f, fmt, vlist);
        va_end(vlist);
        putc('\n', f);
        fflush(f);
        fclose(f);
    }
}
#endif

//
// Prints out the contents of a table if tracing is enabled
//
int aselect_filter_print_table(void * data, const char *key, const char *val)
{
    TRACE2("%s - %s", key, val);
    return 1;
}

// Convert a hex-formatted string into an array of bytes
char *aselect_filter_hex_to_bytes(pool *pPool, char *pcString, int *ccBytes)
{
    int i, length;
    char pcByte[4] = {0, 0, 0, 0};
    char *pcBytes, *pcEnd;

    length = strlen(pcString) >> 1;
    if ((pcBytes = (char *)ap_palloc(pPool, strlen(pcString) >> 1)))
    {
        for (i=0; *pcString; i++)
        {
            pcByte[0] = pcString[0];
            pcByte[1] = pcString[1];
            pcBytes[i] = (char)strtol(pcByte, &pcEnd, 16);
            pcString += 2;
        }
    }
    (*ccBytes) = length;
    return pcBytes;
}

// Convert a byte buffer into a hex string. The result is stored
// in lpResult, which must be big enough to hold the result (length*2+1 characters)
void aselect_filter_bytes_to_hex(const unsigned char *pcBytes, size_t length, char *pcResult)
{
    int i;
    char szTemp[4];

    for (i=0; (size_t)i < length; i++)
    {
        sprintf(szTemp, "%02X", pcBytes[i]);
        memcpy(pcResult+(i*2), szTemp, 2);
    }
    pcResult[length*2] = 0;
}


//
// Reads in a 2 byte error string and converts it to an int
//
int aselect_filter_get_error(pool *pPool, char *pcError)
{
    int iError = ASELECT_FILTER_ERROR_INTERNAL;
    char *pcTemp;
    char pcTemp2[5];
    char *pcTemp3;
    int iLength;

    if ((pcTemp = strstr(pcError, "result_code=")))
    {
        // copy 4 bytes of error code
        memcpy(pcTemp2, pcTemp+12, 4);
        pcTemp2[4] = 0;
        
        TRACE1("aselect_filter_get_error: error: %s", pcTemp2);
        if ((pcTemp3 = aselect_filter_hex_to_bytes(pPool, pcTemp2, &iLength)))
        {
            iError = pcTemp3[0];
            iError <<= 8;
            iError |= pcTemp3[1];
            //TRACE2("aselect_filter_get_error: length=%d, error=%d", iLength, iError);
        }
    }
    return iError;
}


// Replace pcTag in pcSource with pcValue
char *aselect_filter_replace_tag(pool *pPool, char *pcTag, char *pcValue, char *pcSource)
{
    char    *pcDest = NULL;
    int     ccDest;
    char    *pcTemp;
    int     ccTag;
    int     i;

    //
    // Calculate new html size
    // size of template - length of tag + length of url + 1 for "\0"
    //
    ccTag = strlen(pcTag);
    ccDest = strlen(pcSource) - ccTag + strlen(pcValue) + 1;

    if ((pcDest = (char *) (ap_palloc(pPool, ccDest))))
    {
        //
        // Copy part of the source up till the tag
        //
        if ((pcTemp = strstr(pcSource, pcTag)))
        {
            i = pcTemp - pcSource;

            memcpy(pcDest, pcSource, i);
            memcpy(pcDest + i, pcValue, strlen(pcValue));
            memcpy(pcDest + i + strlen(pcValue), pcSource + i + ccTag, strlen(pcSource) - i);

            *(pcDest + ccDest) = '\0';
        }
    }
    else
    {
        pcDest = NULL;
    }

    return pcDest;
}


//
// strips any parameters from the string
// effectivly deletes everything after the ?
//
char *aselect_filter_strip_param(pool *pPool, char * pcASelectServerURL)
{
    char *pcReturn = NULL;
    char *pcTemp;

    if ((pcTemp = strstr(pcASelectServerURL , "?")))
        pcReturn = ap_pstrndup(pPool, pcASelectServerURL, strlen(pcASelectServerURL) - strlen(pcTemp));
    else
        pcReturn = ap_pstrdup(pPool, pcASelectServerURL);

    return pcReturn;
}


//
// Loops until enough data is received or a "\r" is received
// returns number of bytes received, returns -1 if error has occured
//
int aselect_filter_receive_msg(int sd, char *pcReceiveMsg, int ccReceiveMsg)
{
    int iReceived = 0;
    int iRemaining = ccReceiveMsg;
    char *pMsg = pcReceiveMsg;
    char *pLF;
    int cnt;
    static int count = 1000;
    cnt = ++count;

    TRACE3("RCV[%d] aselect_filter_receive_msg (%d): %x", cnt, ccReceiveMsg, pcReceiveMsg);

    // Receive data while their is data or till we find a "\r"
    while ((iRemaining > 0) && ((iReceived = recv(sd, pMsg, iRemaining, 0)) > 0))
    {
        if (iReceived == -1)
            break;
        if ((pLF = strchr(pMsg, '\r')))
        {
            iRemaining -= (pLF-pMsg);
            break;
        }
        iRemaining -= iReceived;
        pMsg += iReceived;
    }

    if (iReceived != -1)
        iReceived = ccReceiveMsg - iRemaining;
        
    TRACE4("RCV[%d] aselect_filter_receive_msg %d: [%.*s]", cnt, iReceived, iReceived, pcReceiveMsg);
    return iReceived;
}


//
// Connect to ASelect Agent send request and wait for response
//
char *aselect_filter_send_request(server_rec *pServer, pool *pPool, char *pcASAIP, int iASAPort, char *pcSendMessage, int ccSendMessage)
{
    int                 sd;
    struct sockaddr_in  pin;
    struct hostent *    hp;
    int                 timeout;
    char                pcReceiveMessage[ASELECT_FILTER_MAX_RECV+1];
    int                 ccReceiveMessage;
    char                *pcResponse = NULL;
    int cnt;
    static int count = 0;
    cnt = ++count;

    TRACE2("ToAGENT[%d] aselect_filter_send_request { [%s]", cnt, pcSendMessage);
    memset(pcReceiveMessage, 0, ASELECT_FILTER_MAX_RECV);

    //
    // Retrieve the host information
    //
    if ((hp = gethostbyname(pcASAIP)) != NULL) {
        //
        // Initialize the connection information
        //
        memset(&pin, 0, sizeof(pin));
        pin.sin_family = AF_INET;
        pin.sin_addr.s_addr = ((struct in_addr *)(hp->h_addr))->s_addr;
        pin.sin_port = htons(iASAPort); 
    }
    else {
        //
        // gethostbyname failed, so try IP address
        //
        memset(&pin, 0, sizeof(pin)); pin.sin_family = AF_INET; pin.sin_addr.s_addr = inet_addr(pcASAIP); pin.sin_port = htons(iASAPort);
    }

    //
    // Create a socket
    //
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        //
        // Connect using connection information
        //
        if (connect(sd,(struct sockaddr *) &pin, sizeof(pin)) != -1)
        {
            //
            // set the socket timeouts on the send and receive
            //
            // SO_SNDTIMEO - send timeout
            // SO_RCVTIMEO - receive timeout
            //
            timeout = ASELECT_FILTER_SOCKET_TIME_OUT;

            if (setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, (char*) &timeout, sizeof(timeout)) != -1)
            {
                //
                // Could not connect to specified address and port
                //
                TRACE1("could not set socket send timeout (%d)", errno);
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, pServer,
                    ap_psprintf(pPool, "ASELECT_FILTER:: could not set socket send timeout (%d)", errno));
            }

            if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*) &timeout, sizeof(timeout)) != -1)
            {
                TRACE1("could not set socket receive timeout (%d)", errno);
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, pServer,
                    ap_psprintf(pPool, "ASELECT_FILTER:: could not set socket receive timeout (%d)", errno));
            }

            //
            // Check if information is not too large for message
            //
            if ((ccSendMessage + 1) < ASELECT_FILTER_MAX_MSG)
            {
                //
                // Send the message
                //
                if (send(sd, (void *) pcSendMessage, (ccSendMessage + 1), 0) > 0)
                {
                    //
                    // Message has been sent, now wait for response
                    //
                    if ((ccReceiveMessage = aselect_filter_receive_msg(sd, pcReceiveMessage, sizeof(pcReceiveMessage)-1)) > 0)
                    {
			TRACE1("ccReceiveMessage=%d",ccReceiveMessage);
                        if (ccReceiveMessage == sizeof(pcReceiveMessage)-1)
                        {
                            // Received message too large
                            TRACE1("received message too large (%d)", ccReceiveMessage);
                            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pServer,
                                "ASELECT_FILTER:: message from A-Select Agent too large");
                        }
                        else
                        {
                            pcResponse = ap_pstrndup(pPool, pcReceiveMessage, ccReceiveMessage);
                            *(pcResponse + ccReceiveMessage) = '\0';
                        }
                    }
                    else
                    {
                        //
                        // Could not receive data
                        //
                        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pServer,
                            ap_psprintf(pPool, "ASELECT_FILTER:: error while receiving data from A-Select Agent (%d)", errno));
                    }
                }
                else
                {
                    //
                    // Could not send data
                    //
                    TRACE1("error while sending data to A-Select Agent (%d)", errno);
                    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pServer,
                        ap_psprintf(pPool, "ASELECT_FILTER:: error while sending data to A-Select Agent (%d)", errno));
                }
            }
            else
            {
                //
                // Message is too large for sending
                //
                TRACE("Message is too large for sending");
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pServer,
                        "ASELECT_FILTER:: message is too large for sending");
            }

        } // connect 
        else
        {
            //
            // Could not connect to specified address and port
            //
            TRACE3("could connect to A-Select Agent at %s:%d (%d)", 
                pcASAIP, iASAPort, errno);
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pServer,
                ap_psprintf(pPool, "ASELECT_FILTER:: could connect to A-Select Agent at %s:%d (%d)", pcASAIP, iASAPort, errno));
        }

        close(sd);

    } // socket
    else
    {
        //
        // Could not create socket
        //
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, pServer,
            ap_psprintf(pPool, "ASELECT_FILTER:: could not create socket (%d)", errno));
    }

    TRACE2("} FromAGENT[%d] aselect_filter_send_request, response=[%s]", cnt, pcResponse?pcResponse:"NULL");
    return pcResponse;
}


char *aselect_filter_get_param(pool *pPool, char *pcArgs, char *pcParam, char *pcDelimiter, int bUrlDecode)
{
    char            *pcTemp;
    char            *pcTemp2;
    char            *pcValue = NULL;
    int             ccValue = 0;
    char *p;

    //TRACE2("aselect_filter_get_param: %s args=%s", pcParam, pcArgs);
    if (pcArgs) {
	// Bauke: example args: my_uid=9876&uid2=0000&uid=1234&...
	//        get parameter "uid=" must result in: 1234
	// NOTE: Delimiter is a single character, but in pcArgs it can be followed by a space!
	// pcParam has a '=' at the end
	for (p = pcArgs; p != NULL; p = pcTemp+1) {
	    pcTemp = strstr(p, pcParam);
	    if (!pcTemp)
		break;
	    //TRACE2("aselect_filter_get_param: 1.TEMP=%s '%c'", pcTemp, (pcTemp==pcArgs)? '#': *(pcTemp-1));
	    //TRACE3("%d %d %d", (pcTemp==pcArgs), *(pcTemp-1) == *pcDelimiter, *(pcTemp-1) == ' ');
	    if (pcTemp==pcArgs || *(pcTemp-1) == *pcDelimiter || *(pcTemp-1) == ' ') {
		break;
	    }
	}

        if (pcTemp) {
            // Update pointer to point to parameter data 
            pcTemp = pcTemp + strlen(pcParam);

            // Found the query parameter attribute
            if ((pcTemp2 = strstr(pcTemp, pcDelimiter))) {
                ccValue = pcTemp2 - pcTemp;
            }
            else {
                ccValue = strlen(pcTemp);
            }

	    //TRACE3("Value=%.*s %d", ccValue, pcTemp, ccValue);
            if (ccValue >= 0) {
                pcValue = ap_pstrndup(pPool, pcTemp, ccValue+1);
                if (pcValue) {
                    *(pcValue + ccValue) = '\0';
                    if (bUrlDecode)
                        aselect_filter_url_decode(pcValue);
                }
                else { // Not enough memory, Set error
                    pcValue = NULL;
                }
            }
            else { // parameter value is empty
            }
        }
        else { // Arguments do not contain parameters
        }
    }
    else { // No arguments to read, return error
    }
    //TRACE2("aselect_filter_get_param: %s %.80s", pcParam, pcValue?pcValue:"NULL");
    return pcValue;
}

/**
 * Encode a string as application/x-www-form-urlencoded.
 * The result is returned in a newly allocated string.
 */
char *aselect_filter_url_encode(pool *pPool, const char *pszValue)
{
    static char *_safe = ".-*_";
    char szHex[4];
    int len;
    char *s, *result;

    // Calculate required length
    len = 0;
    for (s=(char *)pszValue; *s; ++s)
    {
        if (isalnum(*s) ||
            (strchr(_safe, *s) != NULL) ||
            (*s == ' '))
            ++len;
        else
            len += 3;
    }

    result = s = (char *)ap_palloc(pPool, len+1);
    for (; *pszValue; ++pszValue)
    {
        if (isalnum(*pszValue) ||
            (strchr(_safe, *pszValue) != NULL))
        {
            // no change
            *(s++) = *pszValue;
        }
        else if (*pszValue == ' ')
        {
            // convert space to +
            *(s++) = '+';
        }
        else
        {
            // convert to %xx
            sprintf(szHex, "%02x", *pszValue);
            *(s++) = '%';
            *(s++) = szHex[0];
            *(s++) = szHex[1];
        }
    }
    *s = 0;
    return result;
}

/**
 * Decode an URL encoded string
 */
int aselect_filter_url_decode(char *pszValue)
{
    static char *_hexchars = "0123456789abcdef";
    char *nh, *nl;
    int v;

    for (; *pszValue; ++pszValue)
    {
        if (*pszValue == '+')
            *pszValue = ' ';
        else if (*pszValue == '%')
        {
            // decode %xx character
            nh = strchr(_hexchars, tolower(pszValue[1]));
            nl = strchr(_hexchars, tolower(pszValue[2]));
            if (nl == NULL || nh == NULL)
                return FALSE;
            v = (nl-_hexchars) + ((nh-_hexchars)<<4);
            memmove(pszValue+1, pszValue+3, strlen(pszValue)-1);
            *pszValue = v;
        }
    }
    return TRUE;
}

void aselect_filter_add_nocache_headers(table *headers_out)
{
    ap_table_add(headers_out, "Pragma", "no-cache");
    ap_table_add(headers_out, "Cache-Control", "no-cache, no-store, must-revalidate");
    ap_table_add(headers_out, "Expires", "-1");
}

int aselect_filter_gen_error_page(pool *pPool, request_rec *pRequest, int iError, char *pcErrorTemplate)
{
    table   *headers_out = pRequest->headers_out;
    char    *pcErrorHTML, *pcContinueURL;
    char    pcError[256];
    int     iRet;

    TRACE("aselect_filter_gen_error_page()");

    iRet = ASELECT_FILTER_ERROR_FAILED;
    pRequest->content_type = "text/html";
    aselect_filter_add_nocache_headers(headers_out);
    ap_send_http_header(pRequest);
    sprintf(pcError, "%x", iError);

    pcErrorHTML = pcErrorTemplate;
    while (pcErrorHTML && (strstr(pcErrorHTML, "[error_code]") != NULL))
	    pcErrorHTML = aselect_filter_replace_tag(pPool, "[error_code]", pcError, pcErrorHTML);

    // Bauke: Added to facilitate a Continue button
    // NOTE: app_url is only available on successful calls
    if (pRequest->parsed_uri.port == 0)
	pcContinueURL = ap_psprintf(pPool, "http://%s/%s", pRequest->hostname, pRequest->parsed_uri.path);
    else
	pcContinueURL = ap_psprintf(pPool, "http://%s:%d/%s", pRequest->hostname, pRequest->parsed_uri.port, pRequest->parsed_uri.path);
    TRACE1("ContinueUrl=%s", pcContinueURL);
    while (pcErrorHTML && (strstr(pcErrorHTML, "[continue_url]") != NULL))
	    pcErrorHTML = aselect_filter_replace_tag(pPool, "[continue_url]", pcContinueURL, pcErrorHTML);
    // end of add

    if (pcErrorHTML)
    {
	ap_rprintf(pRequest, "%s\n", pcErrorHTML);
	iRet = ASELECT_FILTER_ERROR_OK;
    }
    return iRet;
}

// 20091224, Bauke: prevent repeated addition of the same arguments
// 'urlAndArgs' may contain: request=aselect_show_bar&aselect_app_url=<encoded_url>
// We don't want to repeat that.
char *constructShowBarURL(pool *pPool, char *urlAndArgs)
{
    char *pcSep;
    char *pcEncodedUrl;

    TRACE1("constructShowBarURL, urlAndArgs=%s", urlAndArgs);
    if (strstr(urlAndArgs, "request=aselect_show_bar&aselect_app_url=") != NULL)
	return urlAndArgs;

    pcSep = (strchr(urlAndArgs, '?')) ? "&" : "?";
    pcEncodedUrl = aselect_filter_url_encode(pPool, urlAndArgs);
    urlAndArgs = ap_psprintf(pPool, "%s%srequest=aselect_show_bar&aselect_app_url=%s", urlAndArgs, pcSep, pcEncodedUrl);
    return urlAndArgs;
}

//
// Generate a client-side (HTML) redirection page.
// This function is used after a succesful "verify_credentials"
//
int aselect_filter_gen_authcomplete_redirect(pool * pPool, request_rec *pRequest, PASELECT_FILTER_CONFIG pConfig)
{
    table   *headers_out = pRequest->headers_out;
    int     bArgs;
    char    *pcURI;
    char    *pcURL;
    char    *pcSep;
    char    *pcRedirectURL;

    pRequest->content_type = "text/html";
    aselect_filter_add_nocache_headers(headers_out);
    ap_send_http_header(pRequest);
   
    bArgs = (pConfig->iRedirectMode == ASELECT_FILTER_REDIRECT_FULL &&
			pRequest->args != NULL && *pRequest->args != 0);

    if (*pConfig->pCurrentApp->pcRedirectURL) {
	pcRedirectURL = pConfig->pCurrentApp->pcRedirectURL;
	TRACE3("RedirectURL=%s, Args=%s, bArgs=%d", pcRedirectURL, pRequest->args, bArgs);
        if (bArgs) {
	    pcRedirectURL = ap_psprintf(pPool, "%s%s", pcRedirectURL, pRequest->args);
        }
        else {
	    pcRedirectURL = pConfig->pCurrentApp->pcRedirectURL;
	}
	TRACE2("RedirectURL=%s, UseBar=%d", pcRedirectURL, pConfig->bUseASelectBar);
	if (pConfig->bUseASelectBar) {
	    pcRedirectURL = constructShowBarURL(pPool, pcRedirectURL);
	}        
	TRACE1("---- pcRedirectURL %s", pcRedirectURL);
    }
    else {
	TRACE3("No RedirectURL, URI=%s, Args=%s, bArgs=%d", pRequest->uri, pRequest->args, bArgs);
	if (!bArgs)
	    pcURI = pRequest->uri;
	else {
	    pcURI = ap_psprintf(pPool, "%s%s", pRequest->uri, pRequest->args);
	    pcSep = strstr(pcURI, "a-select-server=");
	    if (pcSep != NULL) {
		*(pcSep-1) = 0;
		if (strchr(pcURI, '?') == NULL)
		    bArgs = FALSE;
	    }
	}
	TRACE2("pcURI=%s, UseBar=%d", pcURI, pConfig->bUseASelectBar);
	if (pConfig->bUseASelectBar) {
	    pcURL = constructShowBarURL(pPool, pcURI);
	}
	else
	    pcURL = pcURI;
    
	TRACE1("---- pcURL %s", pcURL);
	pcRedirectURL = ap_construct_url(pPool, pcURL, pRequest);
    }

    TRACE1("aselect_filter_gen_authcomplete_redirect:: redirecting to: %s", pcRedirectURL);
    ap_rprintf(pRequest, ASELECT_FILTER_CLIENT_REDIRECT, pcRedirectURL, pcRedirectURL);
    return DONE;
}


//
// Set top frame to redirect to a-select-server
//
int aselect_filter_gen_top_redirect(pool *pPool, char *addedSecurity, request_rec *pRequest, char *pcASUrl, char *pcASelectServer, char *pcRID)
{
    table   *headers_out = pRequest->headers_out;
    char    *pcRedirectURL;
    char    *pcASelectServerURL;
    char    *pcCookie;

    TRACE3("aselect_filter_gen_top_redirect::\"%s\",\"%s\",\"%s\"", pcASUrl, pcASelectServer, pcRID); 
    pRequest->content_type = "text/html";

    //
    // save the aselect-server-url parameter which is need to kill the ticket
    // but first strip any parameters from the url
    //
    pcASelectServerURL = aselect_filter_strip_param(pPool, pcASUrl);
    pcCookie = ap_psprintf(pPool, "aselectserverurl=%s; version=1; path=/;%s", pcASelectServerURL, addedSecurity);
    ap_table_add(headers_out, "Set-Cookie", pcCookie);
    TRACE1("Set-Cookie: %s", pcCookie);

    aselect_filter_add_nocache_headers(headers_out);
    ap_send_http_header(pRequest);

    pcRedirectURL = ap_psprintf(pPool, "%s&a-select-server=%s&rid=%s", pcASUrl, pcASelectServer, pcRID);
    ap_rprintf(pRequest, ASELECT_FILTER_CLIENT_REDIRECT, pcRedirectURL, pcRedirectURL);

    return DONE;
}


//
// Checks the config for the URI and if it exists return the corresponding App ID
//
int aselect_filter_verify_directory(pool *pPool, PASELECT_FILTER_CONFIG pConfig, char *pcUri)
{
    int iRet;
    int i = 0;

    iRet = ASELECT_FILTER_ERROR_FAILED;

    for (i = 0; i < pConfig->iAppCount; i++)
    {
        TRACE4("aselect_filter_verify_directory::comparing directory(%d):\"%s\" to URI: \"%s\", enabled=%d", 
            i, pConfig->pApplications[i].pcLocation, pcUri, pConfig->pApplications[i].bEnabled);
        if (strstr(pcUri, pConfig->pApplications[i].pcLocation) != NULL)
        {
	    TRACE("aselect_filter_verify_directory::match"); 
            if (pConfig->pApplications[i].bEnabled)
            {
                pConfig->pCurrentApp = &pConfig->pApplications[i];
                i = pConfig->iAppCount;
                iRet = ASELECT_FILTER_ERROR_OK;
                break;
            }
            // App found, but protection was disabled
        }
    }

    return iRet;
}

//
// aselect_filter_get_cookie retrieves the request cookie and returns the cookie as a string
//
char *aselect_filter_get_cookie(pool *pPool, table *headers_in, char *pcAttribute)
{
    char        *pcValues;
    char        *pcValue = NULL;

    TRACE1("aselect_filter_get_cookie: %s", pcAttribute);
    if ((pcValues = (char *) ap_table_get(headers_in, "Cookie")))
    {
	TRACE1("aselect_filter_get_cookie: pcValues=%s", pcValues);
        if ((pcValue = aselect_filter_get_param(pPool, pcValues, pcAttribute, ";", FALSE)))
        {
            TRACE2("Get-Cookie: %s%s", pcAttribute, pcValue);
        }
        else
        {
	    TRACE1("Get-Cookie: not found in [%s]", pcValues);
            pcValue = NULL;
        }
    }
    else
    {
	TRACE("aselect_filter_get_cookie: No Cookies");
        //
        // No cookies to read, return error
        //
        pcValue = NULL;
    }

    return pcValue;
}

int aselect_filter_show_barhtml(pool *pPool, request_rec *pRequest, PASELECT_FILTER_CONFIG pConfig, char *pcASelectAppURL)
{
    table   *headers_out = pRequest->headers_out;

    TRACE2("aselect_filter_show_barhtml: loc=%s url=%s", pConfig->pCurrentApp->pcLocation, pcASelectAppURL);
    pRequest->content_type = "text/html";
    aselect_filter_add_nocache_headers(headers_out);

    ap_send_http_header(pRequest);
    ap_rprintf(pRequest, ASELECT_LOGOUT_BAR_FRAME, pConfig->pCurrentApp->pcLocation, pcASelectAppURL);
    return DONE;
}



/*
 * Decode a base64-encoded string into a byte array (allocated
 * by this function).
 * Returns the decoded byte array, or NULL on error
 */
char *aselect_filter_base64_decode(pool *pPool, const char *pszValue)
{
    static const char *_base64 =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    char *szDest;
    int iDest, iDestCount;
    int state;
    char *pPos;
    int iPos;

    iDestCount = strlen(pszValue);
    if ((iDestCount & 0x3) != 0)
        return NULL;        // Source length must be multiple of 4
    iDestCount = (iDestCount * 3) / 4;
    szDest = (char *)pszValue;
    pszValue = ap_pstrdup(pPool, pszValue);    
    memset(szDest, 0, iDestCount+1);

    TRACE2("decoding %.200s into %d bytes", pszValue, iDestCount);
    for (state=iDest=0; *pszValue; ++pszValue)
    {
        if (*pszValue == '=')
            break;              // We're done

        pPos = strchr(_base64, *pszValue);
        if (pPos == 0)          // Illegal character in source
            return NULL;
        iPos = pPos - _base64;

        switch (state)
        {
        case 0:                             // b0: xxxxxx00
            szDest[iDest] = iPos << 2;
            break;
        case 1:                             // b0: 000000xx
            szDest[iDest++] |= iPos >> 4;
            szDest[iDest] =                 // b1: xxxx0000
                (iPos & 0x0f) << 4;
            break;
        case 2:
            szDest[iDest++] |=              // b1: 0000xxxx
                iPos >> 2;
            szDest[iDest] =                 // b2: xx000000
                (iPos & 0x03) << 6;
            break;
        case 3:                             // b2: 00xxxxxx
            szDest[iDest++] |= iPos;
            break;
        }
        state = (++state) & 0x3;
    }

    TRACE2("decoded %d bytes: %s", iDest, szDest);
    return szDest;
}

// Bauke, 20080703: added
char *aselect_filter_base64_encode(pool *pPool, const char *pszValue)
{
    static char *base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *retBuf, *pRet;
    int i = 0, j = 0;
    unsigned int len;
    unsigned char code3[3], code4[4];

    const char *porig = pszValue;
    len = strlen(pszValue);
    pRet = retBuf = (char *)ap_palloc(pPool, (4*len+12)/3);
    while (len--) {
	code3[i++] = *(pszValue++);
	if (i == 3) {
	    code4[0] = (code3[0] & 0xfc) >> 2;
	    code4[1] = ((code3[0] & 0x03) << 4) + ((code3[1] & 0xf0) >> 4);
	    code4[2] = ((code3[1] & 0x0f) << 2) + ((code3[2] & 0xc0) >> 6);
	    code4[3] = code3[2] & 0x3f;

	    for(i = 0; (i <4) ; i++)
		*pRet++ = base64Chars[code4[i]];
	    i = 0;
	}
    }

    if (i) {
	for(j = i; j < 3; j++)
	    code3[j] = '\0';

	code4[0] = (code3[0] & 0xfc) >> 2;
	code4[1] = ((code3[0] & 0x03) << 4) + ((code3[1] & 0xf0) >> 4);
	code4[2] = ((code3[1] & 0x0f) << 2) + ((code3[2] & 0xc0) >> 6);
	code4[3] = code3[2] & 0x3f;

	for (j = 0; (j < i + 1); j++)
	    *pRet++ = base64Chars[code4[j]];

	while((i++ < 3))
	    *pRet++ = '=';
    }
    *pRet++ = '\0';
    TRACE2("base64_encoded: %s --> %s", porig, retBuf);
    return retBuf;
}

// Bauke: added debugging info
char *filter_action_text(ASELECT_FILTER_ACTION action)
{
    switch(action) {
    case ASELECT_FILTER_ACTION_ACCESS_GRANTED: return("ACCESS_GRANTED");
    case ASELECT_FILTER_ACTION_ACCESS_DENIED: return("ACCESS_DENIED");
    case ASELECT_FILTER_ACTION_AUTH_USER: return("AUTH_USER");
    case ASELECT_FILTER_ACTION_VERIFY_CREDENTIALS: return("VERIFY_CREDENTIALS");
    case ASELECT_FILTER_ACTION_SET_TICKET: return("SET_TICKET");
    default: return "INVALID_ACTION";
    }
}
