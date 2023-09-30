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
    SessionRequest req;
    SessionResponse resp;
    int result = EINVAL;

    if ( ( username != NULL ) &&
         ( password != NULL ) &&
         ( reference != NULL ) &&
         ( session != NULL ) &&
         ( buflen > SESSION_ID_LEN ) )
    {
        sock = sessionmgr_Connect();
        if( sock >= 0 )
        {
            req.id = SESSION_MANAGER_ID;
            req.version = SESSION_MANAGER_VERSION;
            req.type = SESSION_REQUEST_NEW;

            strncpy( req.username,
                     username,
                     SESSION_MAX_USERNAME_LEN );
            req.username[SESSION_MAX_USERNAME_LEN] = 0;

            strncpy( req.password,
                     password,
                     SESSION_MAX_PASSWORD_LEN );
            req.password[SESSION_MAX_PASSWORD_LEN] = 0;

            strncpy( req.reference,
                     reference,
                     SESSION_MAX_REFERENCE_LEN );
            req.reference[SESSION_MAX_REFERENCE_LEN] = 0;

            len = sizeof( SessionRequest );
            n = write( sock, &req, len );
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
/*  SESSIONMGR_EndSession                                                     */
/*!
    Terminate a session

    The SESSIONMGR_EndSession requests the termination of an existing session

    @param[in]
        session
            pointer to the session identifier

    @retval EOK session terminated successfully
    @retval ENOENT session not found
    @retval EINVAL invalid arguments

==============================================================================*/
int SESSIONMGR_EndSession( char *session )
{
    int sock;
    ssize_t len;
    ssize_t n;
    SessionRequest req;
    SessionResponse resp;
    int result = EINVAL;

    if ( session != NULL )
    {
        sock = sessionmgr_Connect();
        if( sock >= 0 )
        {
            req.id = SESSION_MANAGER_ID;
            req.version = SESSION_MANAGER_VERSION;
            req.type = SESSION_REQUEST_DELETE;

            strncpy( req.sessionId,
                     session,
                     SESSION_ID_LEN );
            req.sessionId[SESSION_ID_LEN] = 0;

            len = sizeof( SessionRequest );
            n = write( sock, &req, len );
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

    @retval EOK session is valid
    @retval EACCES session does not have access
    @retval EINVAL invalid arguments

==============================================================================*/
int SESSIONMGR_Validate( char *session )
{
    int sock;
    ssize_t len;
    ssize_t n;
    SessionRequest req;
    SessionResponse resp;
    int result = EINVAL;

    if ( session != NULL )
    {
        sock = sessionmgr_Connect();
        if( sock >= 0 )
        {
            req.id = SESSION_MANAGER_ID;
            req.version = SESSION_MANAGER_VERSION;
            req.type = SESSION_REQUEST_VALIDATE;

            strncpy( req.sessionId,
                     session,
                     SESSION_ID_LEN );
            req.sessionId[SESSION_ID_LEN] = 0;

            len = sizeof( SessionRequest );
            n = write( sock, &req, len );
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

/*! @}
 * end of libsessionmgr group */

