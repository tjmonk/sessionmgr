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

#ifndef SESSIONMGR_H
#define SESSIONMGR_H

/*==============================================================================
        Includes
==============================================================================*/

#include <stdint.h>
#include <sys/types.h>
#include <string.h>

/*==============================================================================
        Public definitions
==============================================================================*/

/*! session manager identifier 'SMGR' */
#define SESSION_MANAGER_ID  0x534D4752

/*! session manager version */
#define SESSION_MANAGER_VERSION 0x00000001

#ifndef SESSION_MAX_USERNAME_LEN
/*! maximum session username length */
#define SESSION_MAX_USERNAME_LEN    128
#endif

#ifndef SESSION_MAX_PASSWORD_LEN
/*! maximum session password length */
#define SESSION_MAX_PASSWORD_LEN    128
#endif

#ifndef SESSION_MAX_REFERENCE_LEN
/*! maximum session reference length */
#define SESSION_MAX_REFERENCE_LEN   128
#endif

#ifndef SESSION_MAX_TOKEN_LEN
/*! maximum token length */
#define SESSION_MAX_TOKEN_LEN       2048
#endif

#ifndef SESSION_MAX_RESPONSE_LEN
/*! maximum session response length */
#define SESSION_MAX_RESPONSE_LEN   128
#endif

#ifndef SESSION_ID_LEN
/*! session identifier length */
#define SESSION_ID_LEN  64
#endif

#ifndef SESSION_USER_MAX_GROUPS
#define SESSION_USER_MAX_GROUPS 10
#endif

/*! Session Manager Endpoint */
#ifndef SESSION_MANAGER_NAME
#define SESSION_MANAGER_NAME "/sessionmgr"
#endif

/*==============================================================================
        Public types
==============================================================================*/

/*! request type */
typedef enum sessionRequestType
{
    /*! invalid request */
    SESSION_REQUEST_INVALID = 0,

    /*! new session request */
    SESSION_REQUEST_NEW = 1,

    /*! close session request */
    SESSION_REQUEST_DELETE = 2,

    /*! validate session request */
    SESSION_REQUEST_VALIDATE = 3,

    /*! new token session request */
    SESSION_REQUEST_NEW_FROM_TOKEN = 4

} SessionRequestType;

/*! session request */
typedef struct sessionRequest
{
    /*! session request identifier, should be SESSION_MANAGER_ID */
    uint32_t id;

    /*! session request version, should be SESSION_MANAGER_VERSION */
    uint32_t version;

    /*! session manager request type */
    SessionRequestType type;

    /*! payload length */
    size_t payloadlen;

} SessionRequest;

/*! basic authorization request */
typedef struct basicAuthRequest
{
    /*! user name */
    char username[SESSION_MAX_USERNAME_LEN+1];

    /*! password */
    char password[SESSION_MAX_PASSWORD_LEN+1];

    /*! client reference */
    char reference[SESSION_MAX_REFERENCE_LEN+1];

} BasicAuthRequest;

/*! session response */
typedef struct sessionResponse
{
    /*! session request identifier, should be SESSION_MANAGER_ID */
    uint32_t id;

    /*! session request version, should be SESSION_MANAGER_VERSION */
    uint32_t version;

    /*! response code */
    int responseCode;

    /*! response buffer */
    char sessionId[SESSION_ID_LEN+1];

    /*! session user id */
    uid_t uid;

} SessionResponse;

/*==============================================================================
        Public definitions
==============================================================================*/

int SESSIONMGR_NewSession( char *username,
                           char *password,
                           char *reference,
                           char *session,
                           size_t buflen );

int SESSIONMGR_NewSessionFromToken( char *token,
                                    char *reference,
                                    char *session,
                                    size_t buflen );

int SESSIONMGR_NewTokenSession( char *token,
                                char *reference,
                                char *session,
                                size_t buflen );

int SESSIONMGR_EndSession( const char *session );

int SESSIONMGR_Validate( const char *session, uid_t *uid );

char *SESSIONMGR_GetSessionFromCookie( const char *cookie,
                                       char *session,
                                       size_t len );

int SESSIONMGR_Authenticate( const char *session );

#endif
