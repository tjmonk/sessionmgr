/*==============================================================================
MIT License

Copyright (c) 2023 Trevor Monk

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
==============================================================================*/

/*!
 * @defgroup libsessionmgr libsessionmgr
 * @brief Session Manager Library
 * @{
 */

/*============================================================================*/
/*!
@file sessionmgr.c

    Session Manager Library

    The Session Manager Library provides API functions to interface with
    the session manager to manage user sessions.

*/
/*============================================================================*/

/*==============================================================================
        Includes
==============================================================================*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <signal.h>
#include <sys/un.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <varserver/varserver.h>
#include <sessionmgr/sessionmgr.h>

/*==============================================================================
        Private definitions
==============================================================================*/

/*==============================================================================
        Private function declarations
==============================================================================*/
static int sessionmgr_Connect();
static int sendBasicAuthRequest( int sock, BasicAuthRequest *bar );

/*==============================================================================
        Public function definitions
==============================================================================*/

/*============================================================================*/
/*  SESSIONMGR_NewSession                                                     */
/*!
    Create a new session

    The SESSIONMGR_NewSession requests the creation of a new
    session from the session manager.

    @param[in]
        username
            pointer to the username associated with the session

    @param[in]
        password
            password of the user

    @param[in]
        reference
            a client reference such as an IP address or other unique
            client indicator.  This allows two distinct logins of
            the same user from different locations.

    @param[in,out]
        session
            pointer to a location to store the created session identifier

    @param[in,out]
        buflen
            length of the buffer to store the created session identifier

    @retval EOK session created successfully
    @retval EINVAL invalid arguments

==============================================================================*/
int SESSIONMGR_NewSession( char *username,
                           char *password,
                           char *reference,
                           char *session,
                           size_t buflen )
{
    int sock;
    ssize_t len;
    ssize_t n;
    SessionResponse resp;
    BasicAuthRequest bar;
    int result = EINVAL;

    if ( ( username != NULL ) &&
         ( password != NULL ) &&
         ( reference != NULL ) &&
         ( session != NULL ) &&
         ( buflen > SESSION_ID_LEN ) )
    {
        result = ECONNREFUSED;
        sock = sessionmgr_Connect();
        if( sock >= 0 )
        {
            strncpy( bar.username,
                     username,
                     SESSION_MAX_USERNAME_LEN );
            bar.username[SESSION_MAX_USERNAME_LEN] = 0;

            strncpy( bar.password,
                     password,
                     SESSION_MAX_PASSWORD_LEN );
            bar.password[SESSION_MAX_PASSWORD_LEN] = 0;

            strncpy( bar.reference,
                     reference,
                     SESSION_MAX_REFERENCE_LEN );
            bar.reference[SESSION_MAX_REFERENCE_LEN] = 0;

            result = sendBasicAuthRequest( sock, &bar );

            if ( result == EOK )
            {
                len = sizeof( SessionResponse );
                n = read( sock, &resp, len );
                if ( n != len )
                {
                    result = EBADMSG;
                }
                else
                {
                    if ( resp.responseCode == EOK )
                    {
                        strncpy( session, resp.sessionId, buflen );
                        session[buflen-1] = 0;
                    }

                    result = resp.responseCode;
                }
            }
        }

        close( sock );
    }

    return result;
}

/*============================================================================*/
/*  sendBasicAuthRequest                                                      */
/*!
    Send a Basic Authorization Request

    The sendBasicAuthRequest function sends a basic authentication
    request to the session manager server.

    @param[in]
        socker
            open socket to the session manager server

    @param[in]
        bar
            pointer to the BasicAuthRequest object to send

    @retval EOK Basic Auth Request sent
    @retval EINVAL invalid arguments
    @retval EBADMSG incorrect number of sent bytes

==============================================================================*/
static int sendBasicAuthRequest( int sock, BasicAuthRequest *bar )
{
    SessionRequest req;
    struct iovec iov[2];
    size_t len;
    size_t n;
    int result = EINVAL;

    if ( ( bar != NULL ) &&
         ( sock != -1 ) )
    {
        req.id = SESSION_MANAGER_ID;
        req.version = SESSION_MANAGER_VERSION;
        req.type = SESSION_REQUEST_NEW;
        req.payloadlen = sizeof(BasicAuthRequest);

        iov[0].iov_base = &req;
        iov[0].iov_len = sizeof(SessionRequest);

        iov[1].iov_base = bar;
        iov[1].iov_len = sizeof(BasicAuthRequest);

        len = iov[0].iov_len + iov[1].iov_len;
        n = writev( sock, iov, 2);
        result = ( n == len ) ? EOK : EBADMSG;
    }

    return result;
}

/*============================================================================*/
/*  SESSIONMGR_NewSessionFromToken                                            */
/*!
    Create a new session from a bearer token

    The SESSIONMGR_NewSessionFromToken requests the creation of a new
    session from the session manager using a bearer token for
    authentication.

    @param[in]
        token
            pointer to the bearer token to use for authentication

    @param[in]
        reference
            a client reference such as an IP address or other unique
            client indicator.  This allows two distinct logins of
            the same user from different locations.

    @param[in,out]
        session
            pointer to a location to store the created session identifier

    @param[in,out]
        buflen
            length of the buffer to store the created session identifier

    @retval EOK session created successfully
    @retval EINVAL invalid arguments

==============================================================================*/
int SESSIONMGR_NewSessionFromToken( char *token,
                                    char *reference,
                                    char *session,
                                    size_t buflen )
{
    int sock;
    struct iovec iov[3];
    char sessionref[SESSION_MAX_REFERENCE_LEN+1];
    size_t l;
    ssize_t len;
    ssize_t n;
    SessionRequest req;
    SessionResponse resp;
    int result = EINVAL;

    if ( ( token != NULL ) &&
         ( reference != NULL ) &&
         ( session != NULL ) &&
         ( buflen > SESSION_ID_LEN ) )
    {
        result = ECONNREFUSED;

        l = strlen( token ) + 1;
        if ( l <= SESSION_MAX_TOKEN_LEN )
        {
            sock = sessionmgr_Connect();
            if( sock >= 0 )
            {
                strncpy( sessionref,
                         reference,
                         SESSION_MAX_REFERENCE_LEN );
                sessionref[SESSION_MAX_REFERENCE_LEN] = 0;

                req.id = SESSION_MANAGER_ID;
                req.version = SESSION_MANAGER_VERSION;
                req.type = SESSION_REQUEST_NEW_FROM_TOKEN;
                req.payloadlen = l;

                iov[0].iov_base = &req;
                iov[0].iov_len = sizeof(SessionRequest);

                iov[1].iov_base = sessionref;
                iov[1].iov_len = sizeof(sessionref);

                iov[2].iov_base = token;
                iov[2].iov_len = req.payloadlen;

                len = iov[0].iov_len + iov[1].iov_len + iov[2].iov_len;
                n = writev( sock, iov, 3);
                result = ( n == len ) ? EOK : EBADMSG;
                if ( result == EOK )
                {
                    len = sizeof( SessionResponse );
                    n = read( sock, &resp, len );
                    if ( n != len )
                    {
                        result = EBADMSG;
                    }
                    else
                    {
                        if ( resp.responseCode == EOK )
                        {
                            strncpy( session, resp.sessionId, buflen );
                            session[buflen-1] = 0;
                        }

                        result = resp.responseCode;
                    }
                }
            }

            close( sock );
        }
    }

    return result;

}

/*============================================================================*/
/*  SESSIONMGR_EndSession                                                     */
/*!
    Terminate a session

    The SESSIONMGR_EndSession requests the termination of an existing session

    @param[in]
        session
            pointer to the session identifier

    @retval EOK session terminated successfully
    @retval ENOENT session not found
    @retval E2BIG session string is too big
    @retval EINVAL invalid arguments

==============================================================================*/
int SESSIONMGR_EndSession( const char *session )
{
    int sock;
    ssize_t len;
    size_t l;
    ssize_t n;
    SessionRequest req;
    SessionResponse resp;
    struct iovec iov[2];
    int result = EINVAL;

    if ( session != NULL )
    {
        l = strlen( session );
        if ( l <= SESSION_ID_LEN )
        {
            sock = sessionmgr_Connect();
            if( sock >= 0 )
            {
                req.id = SESSION_MANAGER_ID;
                req.version = SESSION_MANAGER_VERSION;
                req.type = SESSION_REQUEST_DELETE;
                req.payloadlen = l;

                iov[0].iov_base = &req;
                iov[0].iov_len = sizeof(SessionRequest);

                iov[1].iov_base = (void *)session;
                iov[1].iov_len = l;

                len = iov[0].iov_len + iov[1].iov_len;
                n = writev( sock, iov, 2 );
                if ( n != len )
                {
                    result = EBADMSG;
                }
                else
                {
                    len = sizeof( SessionResponse );
                    n = read( sock, &resp, len );
                    if ( n != len )
                    {
                        result = EBADMSG;
                    }
                    else
                    {
                        result = resp.responseCode;
                    }
                }
            }

            close( sock );
        }
        else
        {
            result = E2BIG;
        }
    }

    return result;
}

/*============================================================================*/
/*  SESSIONMGR_Validate                                                       */
/*!
    Validate a session

    The SESSIONMGR_Validate checks to see if the specified session token
    corresponds to a valid session.

    @param[in]
        session
            pointer to the session identifier

    @param[in,out]
        uid
            pointer to a location to store the session user id

    @retval EOK session is valid
    @retval EACCES session does not have access
    @retval EINVAL invalid arguments

==============================================================================*/
int SESSIONMGR_Validate( const char *session, uid_t *uid )
{
    int sock;
    ssize_t len;
    ssize_t n;
    size_t l;
    SessionRequest req;
    SessionResponse resp;
    struct iovec iov[2];
    int result = EINVAL;

    if ( ( session != NULL ) &&
         ( uid != NULL ) )
    {
        l = strlen( session );
        if ( l <= SESSION_ID_LEN )
        {
            sock = sessionmgr_Connect();
            if( sock >= 0 )
            {
                req.id = SESSION_MANAGER_ID;
                req.version = SESSION_MANAGER_VERSION;
                req.type = SESSION_REQUEST_VALIDATE;
                req.payloadlen = l;

                iov[0].iov_base = &req;
                iov[0].iov_len = sizeof(SessionRequest);

                iov[1].iov_base = (void *)session;
                iov[1].iov_len = l;

                len = iov[0].iov_len + iov[1].iov_len;
                n = writev( sock, iov, 2 );
                if ( n != len )
                {
                    result = EBADMSG;
                }
                else
                {
                    len = sizeof( SessionResponse );
                    n = read( sock, &resp, len );
                    if ( n != len )
                    {
                        result = EBADMSG;
                    }
                    else
                    {
                        result = resp.responseCode;
                        if ( result == EOK )
                        {
                            *uid = resp.uid;
                        }
                    }
                }
            }

            close( sock );
        }
    }

    return result;
}

/*============================================================================*/
/*  sessionmgr_Connect                                                        */
/*!
    Connect to Session Manager

    The sessionmgr_Connect creates a socket and connects it to the session
    manager.

    @retval socket connected to the session manager
    @retval -1 if no connection can be established

==============================================================================*/
static int sessionmgr_Connect()
{
    int sock = -1;
    int rc;
    struct sockaddr_un server;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if ( sock > 0 )
    {
        server.sun_family = AF_UNIX;
        strcpy(server.sun_path, SESSION_MANAGER_NAME );

        rc = connect( sock,
                        (struct sockaddr *) &server,
                        sizeof(struct sockaddr_un));
        if( rc < 0 )
        {
            close( sock );
        }
    }

    return sock;
}

/*============================================================================*/
/*  SESSIONMGR_GetSessionFromCookie                                           */
/*!
    Get a session identifier from within an HTTP cookie

    The SESSIONMGR_GetSessionFromCookie extracts a session identifier
    from within an HTTP cookie.

    An HTTP cookie string is a semicolon separated list of name=value
    pairs.  The name of the session cookie is "session", so this function
    searches for "session=" within the cookie string and returns its
    associated value.

    @param[in]
        cookie
            pointer to a cookie string

    @param[in,out]
        session
            pointer to a buffer to store the session value

    @param[in]
        len
            length of the buffer to store the session value
            ( must be greater than or equal to SESSION_ID_LEN+1 )

    @retval pointer to the session value
    @retval NULL if the session does not exist or cannot be extracted

==============================================================================*/
char *SESSIONMGR_GetSessionFromCookie( const char *cookie,
                                       char *session,
                                       size_t len )
{
    char *p;
    char *start;
    size_t l;
    char *result = NULL;

    if ( ( cookie != NULL ) &&
         ( session != NULL ) &&
         ( len >= SESSION_ID_LEN + 1 ) )
    {
        p = strstr(cookie, "session=");
        if ( p != NULL )
        {
            p += 8;
        }

        start = p;
        p = strchr(start, ';');
        if ( p != NULL )
        {
            l = p - start;
        }
        else
        {
            l = strlen( start );
        }

        if ( l < len )
        {
            memcpy( session, start, l );
            session[l] = 0;

            result = session;
        }
    }

    return result;
}

/*============================================================================*/
/*  SESSIONMGR_Authenticate                                                   */
/*!
    Authenticate and set the effective user id for the session

    The SESSIONMGR_Authenticate authenticates the specified session
    and then sets the effective user identifier for the current
    process to that of the user associated with the session.

    @param[in]
        session
            pointer to the session to authenticate

    @retval EOK session is authenticated
    @retval EINVAL invalid arguments
    @retval EACCES permission denied

==============================================================================*/
int SESSIONMGR_Authenticate( const char *session )
{
    int result = EINVAL;
    uid_t uid;

    if ( session != NULL )
    {
        if ( SESSIONMGR_Validate( session, &uid ) == EOK )
        {
            result = ( seteuid(uid) == 0 ) ? EOK : errno;
        }
        else
        {
            result = EACCES;
        }
    }

    return result;
}

/*! @}
 * end of libsessionmgr group */

