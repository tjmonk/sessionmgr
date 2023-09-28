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
 * @defgroup session Session Client
 * @brief Session Manager Test Client
 * @{
 */

/*============================================================================*/
/*!
@file session.c

    Session Manager Test Client

    The Session Manager Test Client provides a cli interface to the
    session manager via the session manager library to create and
    manage sessions.

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
#include <sessionmgr/sessionmgr.h>

/*==============================================================================
        Private definitions
==============================================================================*/

/*! Session Manager state */
typedef struct sessionState
{
    /*! verbose flag */
    bool verbose;

    /*! show program usage */
    bool usage;

    /*! user name */
    char *username;

    /*! password */
    char *password;

    /*! client reference */
    char *clientref;

} SessionState;

#ifndef EOK
/*! zero means no error */
#define EOK 0
#endif

/*==============================================================================
        function declarations
==============================================================================*/
int main(int argc, char **argv);
static void usage( char *cmdname );
static int ProcessOptions( int argC, char *argV[], SessionState *pState );

/*==============================================================================
        Public function definitions
==============================================================================*/

/*============================================================================*/
/*  main                                                                      */
/*!
    Main entry point for the session client

    The main function parse the command line options
    and executes the appropriate session manager library call

    @param[in]
        argc
            number of arguments on the command line
            (including the command itself)

    @param[in]
        argv
            array of pointers to the command line arguments

    @return none

==============================================================================*/
int main(int argc, char **argv)
{
    int result = EINVAL;
    char session[BUFSIZ];
    SessionState state;

    /* initialize the Session Manager State */
    memset( &state, 0, sizeof (SessionState));

    state.username = "root";
    state.password = "root";
    state.clientref = "session_tester";

    /* Process the command line options */
    ProcessOptions( argc, argv, &state );

    /* create a new session */
    result = SESSIONMGR_NewSession( state.username,
                                    state.password,
                                    state.clientref,
                                    session,
                                    BUFSIZ );

    if ( state.verbose == true )
    {
        if ( result == EOK )
        {
            printf("session = %s\n", session );
        }
        else
        {
            printf("%s\n", strerror( result ));
        }
    }

    return result == EOK ? 0 : 1;
}

/*============================================================================*/
/*  usage                                                                     */
/*!
    Display the application usage

    The usage function dumps the application usage message to stderr.

    @param[in]
       cmdname
            pointer to the invoked command name

    @return none

==============================================================================*/
static void usage( char *cmdname )
{
    if( cmdname != NULL )
    {
        fprintf(stderr,
                "usage: %s [-v] [-h] [-u user] [-p pass] [-r ref]\n"
                " [-v] : verbose mode\n"
                " [-h] : display this help\n"
                " [-u user] : username\n"
                " [-p pass] : password\n"
                " [-r ref] : unique client reference\n",
                cmdname );
    }
}

/*============================================================================*/
/*  ProcessOptions                                                            */
/*!
    Process the command line options

    The ProcessOptions function processes the command line options and
    populates the SessionMgrState object

    @param[in]
        argC
            number of arguments
            (including the command itself)

    @param[in]
        argv
            array of pointers to the command line arguments

    @param[in]
        pState
            pointer to the Session Manager state object

    @return none

==============================================================================*/
static int ProcessOptions( int argC, char *argV[], SessionState *pState )
{
    int c;
    int result = EINVAL;
    const char *options = "vhu:p:r:";

    if( ( pState != NULL ) &&
        ( argV != NULL ) )
    {
        result = EOK;

        while( ( c = getopt( argC, argV, options ) ) != -1 )
        {
            switch( c )
            {
                case 'h':
                    usage( argV[0] );
                    exit( 1 );
                    break;

                case 'v':
                    pState->verbose = true;
                    break;

                case 'u':
                    pState->username = optarg;
                    break;

                case 'p':
                    pState->password = optarg;
                    break;

                case 'r':
                    pState->clientref = optarg;
                    break;

                default:
                    break;
            }
        }
    }

    return result;
}

/*! @}
 * end of session group */

