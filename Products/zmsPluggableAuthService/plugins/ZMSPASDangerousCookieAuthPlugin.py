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
""" Class: ZMSPASDangerousCookieAuthPluginr

$Id$
"""

from __future__ import absolute_import
from __future__ import print_function
from base64 import encodestring, decodestring
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


class IZMSPASDangerousCookieAuthPlugin(Interface):
    """ Marker interface.
    """

manage_addZMSPASDangerousCookieAuthPluginForm = PageTemplateFile(
    'www/zpdcapAdd', globals(), __name__='manage_addZMSPASDangerousCookieAuthPluginForm')


def addZMSPASDangerousCookieAuthPlugin( dispatcher
                       , id
                       , title=None
                       , cookie_name=''
                       , REQUEST=None
                       ):
    """ Add a Dangerous Cookie Auth Plugin to a Pluggable Auth Service. """
    sp = ZMSPASDangerousCookieAuthPlugin(id, title, cookie_name)
    dispatcher._setObject(sp.getId(), sp)

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect( '%s/manage_workspace'
                                      '?manage_tabs_message='
                                      'ZMSPASDangerousCookieAuthPluginr+added.'
                                    % dispatcher.absolute_url() )


class ZMSPASDangerousCookieAuthPlugin(Folder, BasePlugin):
    """ Multi-plugin for managing details of Dangerouse Cookie Authentication. """

    meta_type = 'ZMS PluggableAuthService Dangerous Cookie Auth Plugin'
    cookie_name = '__ginger_snap'
    security = ClassSecurityInfo()

    mock = PageTemplateFile('www/zpdcapMock', globals())

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


    def getSecretKey(self):
        from cryptography.fernet import Fernet
        if not getattr(self,'secret_key',''):
            self.secret_key = Fernet.generate_key()
        return self.secret_key
        
    
    def mockCookie(self, REQUEST):
        """ mockCookie """
        token = None
        if REQUEST.has_key('d'):
          d = REQUEST.get('d','').strip()
          if d.startswith('{') and d.endswith('}'):
            d = eval('(%s)'%d)
            if type(d) is dict:
              token = self.encryptCookie(d)
        if token:
            REQUEST.RESPONSE.setCookie(self.cookie_name, token)
        elif self.cookie_name in REQUEST.cookies:
            REQUEST.RESPONSE.expireCookie(self.cookie_name)             
        return REQUEST.RESPONSE.redirect(REQUEST['HTTP_REFERER'])


    def encryptCookie(self, d):
        from itsdangerous import URLSafeSerializer
        auth_s = URLSafeSerializer(self.getSecretKey())
        token = auth_s.dumps(d)
        return token


    def decryptCookie(self, token):
        try:
            from itsdangerous import URLSafeSerializer
            auth_s = URLSafeSerializer(self.getSecretKey())
            d = auth_s.loads(token)
            return d
        except:
            return None


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


    security.declarePrivate('unauthorized')
    def unauthorized(self):
        req = self.REQUEST
        resp = req['RESPONSE']

        # If we set the auth cookie before, delete it now.
        if self.cookie_name in resp.cookies:
            del resp.cookies[self.cookie_name]

        # Could not challenge.
        return 0


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

classImplements( ZMSPASDangerousCookieAuthPlugin
               , IZMSPASDangerousCookieAuthPlugin
               , ILoginPasswordHostExtractionPlugin
               , IChallengePlugin
               , ICredentialsUpdatePlugin
               , ICredentialsResetPlugin
               )

InitializeClass(ZMSPASDangerousCookieAuthPlugin)