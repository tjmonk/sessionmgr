#!/bin/bash

# pre-requisites:
#   - varserver is running.  You can start it like this: varserver &
#   - sessionmgr is running,  You can start it like this sessionmgr &

# create a test user called bob
NEWUSER=bob
useradd $NEWUSER

# create a random password for bob
password=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 1`

# set bob's password
echo $NEWUSER:$password | chpasswd

# create a new session for bob
echo -n "Creating Session: "
token=`session -m login -u bob -p $password`
if [ $? == 0 ]; then
    echo "PASSED"
else
    echo "FAILED"
fi

# get the sessions
vars -vn session/info

# validate the session
echo -n "Checking session valid: "
session -m validate -s $token
if [ $? == 0 ]; then
    echo "PASSED"
else
    echo "FAILED"
fi

# check invalid password
echo -n "Checking invalid session: "
session -m validate -s fsdhsjdhf
if [ $? == 0 ]; then
    echo FAILED
else
    echo PASSED
fi

# terminate bob's session
echo -n "Terminating session: "
session -m logout -s $token
if [ $? == 0 ]; then
    echo "PASSED"
else
    echo "FAILED"
fi

# check bob's session does not exist
echo -n "Checking bob's session is gone: "
session -m validate -s $token
if [ $? != 0 ]; then
    echo "PASSED"
else
    echo "FAILED"
fi

# check session list
vars -vn session/info

# delete user bob
userdel bob
