# -*- coding: utf-8 -*- 
################################################################################
# ZMSPASCookieAuthHelper.py
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
################################################################################
""" Class: ZMSPASCookieAuthHelper

$Id$
"""

from __future__ import absolute_import
from __future__ import print_function
from base64 import encodebytes, decodebytes
import binascii
from binascii import Error
from six.moves.urllib.parse import quote, unquote

from AccessControl.SecurityInfo import ClassSecurityInfo
from AccessControl.Permissions import view
from AccessControl.class_init import InitializeClass

from OFS.Folder import Folder
from zope.interface import Interface

from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PageTemplates.ZopePageTemplate import ZopePageTemplate

from Products.PluggableAuthService.interfaces.plugins import ILoginPasswordHostExtractionPlugin
from Products.PluggableAuthService.interfaces.plugins import IChallengePlugin
from Products.PluggableAuthService.interfaces.plugins import ICredentialsUpdatePlugin
from Products.PluggableAuthService.interfaces.plugins import ICredentialsResetPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements


class IZMSPASCookieAuthHelper(Interface):
    """ Marker interface.
    """

manage_addZMSPASCookieAuthHelperForm = PageTemplateFile(
    'www/zpcahAdd', globals(), __name__='manage_addZMSPASCookieAuthHelperForm')


def addZMSPASCookieAuthHelper( dispatcher
                       , id
                       , title=None
                       , cookie_name=''
                       , REQUEST=None
                       ):
    """ Add a Cookie Auth Helper to a Pluggable Auth Service. """
    sp = ZMSPASCookieAuthHelper(id, title, cookie_name)
    dispatcher._setObject(sp.getId(), sp)

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect( '%s/manage_workspace'
                                      '?manage_tabs_message='
                                      'ZMSPASCookieAuthHelper+added.'
                                    % dispatcher.absolute_url() )


class ZMSPASCookieAuthHelper(Folder, BasePlugin):
    """ Multi-plugin for managing details of Cookie Authentication. """

    meta_type = 'ZMS PluggableAuthService Cookie Auth Helper'
    zmi_icon = 'fas fa-cookie-bite'
    zmi_show_add_dialog = True
    cookie_name = '__ginger_snap'
    login_path = 'login_form'
    security = ClassSecurityInfo()

    _properties = ( { 'id'    : 'title'
                    , 'label' : 'Title'
                    , 'type'  : 'string'
                    , 'mode'  : 'w'
                    }
                  , { 'id'    : 'cookie_name'
                    , 'label' : 'Cookie Name'
                    , 'type'  : 'string'
                    , 'mode'  : 'w'
                    }
                  , { 'id'     : 'secret_key'
                    , 'label'  : 'Secret Key'
                    , 'type'   : 'string'
                    , 'mode'   : 'w'
                    , 'default': ''
                    }
                  , { 'id'    : 'login_path'
                    , 'label' : 'Login Form'
                    , 'type'  : 'string'
                    , 'mode'  : 'w'
                    }
                  )

    manage_options = ( BasePlugin.manage_options[:1]
                     + Folder.manage_options[:1]
                     + Folder.manage_options[2:]
                     )

    def __init__(self, id, title=None, cookie_name=''):
        self._setId(id)
        self.title = title
        self.secret_key = ''
        if cookie_name:
            self.cookie_name = cookie_name


    def getCipherSuite(self):
        from cryptography.fernet import Fernet
        if not getattr(self,'secret_key',''):
            self.secret_key = Fernet.generate_key()
        cipher_suite = Fernet(self.secret_key)
        return cipher_suite


    def encryptCookie(self, cookie):
        # print("##### encryptCookie",1,cookie)
        try:
            cipher_suite = self.getCipherSuite() 
            cookie = cipher_suite.encrypt(cookie)
        except:
            import sys,traceback
            t,v,tb = sys.exc_info()
            # print("###### encryptCookie: can't",traceback.format_exception(t, v, tb))
            cookie = encodebytes(cookie)
        # print("##### encryptCookie",2,cookie)
        return cookie


    def decryptCookie(self, cookie):
        # print("##### decryptCookie",1,cookie)
        try:
            cipher_suite = self.getCipherSuite() 
            cookie = cipher_suite.decrypt(cookie)
        except:
            import sys,traceback
            t,v,tb = sys.exc_info()
            # print("###### decryptCookie: can't",traceback.format_exception(t, v, tb))
            cookie = decodebytes(cookie)
        # print("##### decryptCookie",2,cookie)
        return cookie


    security.declarePrivate('extractCredentials')
    def extractCredentials(self, request):
        """ Extract credentials from cookie or 'request'. """
        creds = {}
        session = request.SESSION
        cookie = request.get(self.cookie_name, '')
        # Look in the request.form for the names coming from the login form
        login = request.form.get('__ac_name', '')

        if login and '__ac_password' in request.form:
            creds['login'] = login
            creds['password'] = request.form.get('__ac_password', '')

        elif cookie and cookie != 'deleted':
            raw = unquote(cookie)
            try:
                cookie_val = self.decryptCookie(raw.encode('utf8')).decode('utf8')
            except Error:
                # Cookie is in a different format, so it is not ours
                return creds

            try:
                login, password = cookie_val.split(':')
            except ValueError:
                # Cookie is in a different format, so it is not ours
                return creds

            try:
                # creds['login'] = login.decode('hex')
                # creds['password'] = password.decode('hex')
                creds['login'] =  binascii.unhexlify(login.encode('utf8')).decode('utf8')
                creds['password'] = binascii.unhexlify(password.encode('utf8')).decode('utf8')
            except TypeError:
                # Cookie is in a different format, so it is not ours
                return {}

        if creds:
            creds['remote_host'] = request.get('REMOTE_HOST', '')

            try:
                creds['remote_address'] = request.getClientAddr()
            except AttributeError:
                creds['remote_address'] = request.get('REMOTE_ADDR', '')

        return creds


    security.declarePrivate('challenge')
    def challenge(self, request, response, **kw):
        """ Challenge the user for credentials. """
        return self.unauthorized()


    security.declarePrivate('updateCredentials')
    def updateCredentials(self, request, response, login, new_password):
        """ Respond to change of credentials (NOOP for basic auth). """
        # cookie_str = '%s:%s' % (login.encode('hex'), new_password.encode('hex'))
        cookie_str = b'%s:%s'%(binascii.hexlify(login.encode('utf8')), binascii.hexlify(new_password.encode('utf8')))
        cookie_val = self.encryptCookie(cookie_str)
        cookie_val = cookie_val.rstrip()
        response.setCookie(self.cookie_name, quote(cookie_val), path='/')


    security.declarePrivate('resetCredentials')
    def resetCredentials(self, request, response):
        """ Raise unauthorized to tell browser to clear credentials. """
        response.expireCookie(self.cookie_name, path='/')


    security.declarePrivate('manage_afterAdd')
    def manage_afterAdd(self, item, container):
        """ Setup tasks upon instantiation """
        if not 'login_form' in self.objectIds():
            login_form = ZopePageTemplate( id='login_form'
                                           , text=BASIC_LOGIN_FORM
                                           )
            login_form.title = 'Login Form'
            login_form.manage_permission(view, roles=['Anonymous'], acquire=1)
            self._setObject( 'login_form', login_form, set_owner=0 )


    security.declarePrivate('unauthorized')
    def unauthorized(self):
        req = self.REQUEST
        resp = req['RESPONSE']

        # If we set the auth cookie before, delete it now.
        if self.cookie_name in resp.cookies:
            del resp.cookies[self.cookie_name]

        # Redirect if desired.
        url = self.getLoginURL()
        if url is not None:
            came_from = req.get('came_from', None)

            if came_from is None:
                came_from = req.get('ACTUAL_URL', '')
                query = req.get('QUERY_STRING')
                if query:
                    if not query.startswith('?'):
                        query = '?' + query
                    came_from = came_from + query
            else:
                # If came_from contains a value it means the user
                # must be coming through here a second time
                # Reasons could be typos when providing credentials
                # or a redirect loop (see below)
                req_url = req.get('ACTUAL_URL', '')

                if req_url and req_url == url:
                    # Oops... The login_form cannot be reached by the user -
                    # it might be protected itself due to misconfiguration -
                    # the only sane thing to do is to give up because we are
                    # in an endless redirect loop.
                    return 0

            if '?' in url:
                sep = '&'
            else:
                sep = '?'
            url = '%s%scame_from=%s' % (url, sep, quote(came_from))
            resp.redirect(url, lock=1)
            resp.setHeader('Expires', 'Sat, 01 Jan 2000 00:00:00 GMT')
            resp.setHeader('Cache-Control', 'no-cache')
            return 1

        # Could not challenge.
        return 0


    security.declarePrivate('getLoginURL')
    def getLoginURL(self):
        """ Where to send people for logging in """
        if self.login_path.startswith('/') or '://' in self.login_path:
            return self.login_path
        elif self.login_path != '':
            return '%s/%s' % (self.absolute_url(), self.login_path)
        else:
            return None

    security.declarePublic('login')
    def login(self):
        """ Set a cookie and redirect to the url that we tried to
        authenticate against originally.
        """
        request = self.REQUEST
        response = request['RESPONSE']

        login = request.get('__ac_name', '')
        password = request.get('__ac_password', '')

        # In order to use the ZMSPASCookieAuthHelper for its nice login page
        # facility but store and manage credentials somewhere else we need
        # to make sure that upon login only plugins activated as
        # IUpdateCredentialPlugins get their updateCredentials method
        # called. If the method is called on the ZMSPASCookieAuthHelper it will
        # simply set its own auth cookie, to the exclusion of any other
        # plugins that might want to store the credentials.
        pas_instance = self._getPAS()

        if pas_instance is not None:
            pas_instance.updateCredentials(request, response, login, password)

        came_from = request.form['came_from']

        return response.redirect(came_from)

classImplements( ZMSPASCookieAuthHelper
               , IZMSPASCookieAuthHelper
               , ILoginPasswordHostExtractionPlugin
               , IChallengePlugin
               , ICredentialsUpdatePlugin
               , ICredentialsResetPlugin
               )

InitializeClass(ZMSPASCookieAuthHelper)


BASIC_LOGIN_FORM = """<html>
  <head>
    <title> Login Form </title>
  </head>

  <body>

    <h3> Please log in </h3>

    <form method="post" action=""
          tal:attributes="action string:${here/absolute_url}/login">

      <input type="hidden" name="came_from" value=""
             tal:attributes="value request/came_from | string:"/>
      <table cellpadding="2">
        <tr>
          <td><b>Login:</b> </td>
          <td><input type="text" name="__ac_name" size="30" /></td>
        </tr>
        <tr>
          <td><b>Password:</b></td>
          <td><input type="password" name="__ac_password" size="30" /></td>
        </tr>
        <tr>
          <td colspan="2">
            <br />
            <input type="submit" value=" Log In " />
          </td>
        </tr>
      </table>

    </form>

  </body>

</html>
"""

