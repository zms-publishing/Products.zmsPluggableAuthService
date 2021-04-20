# -*- coding: utf-8 -*- 
################################################################################
# ZMSPASSsoPlugin.py
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
""" Class: ZMSPASSsoPlugin

$Id$
"""

import logging

from base64 import encodestring, decodestring
from binascii import Error
from six.moves.urllib.parse import quote, unquote

from AccessControl.SecurityInfo import ClassSecurityInfo
from AccessControl.Permissions import view
from AccessControl.class_init import InitializeClass

from DateTime.DateTime import DateTime

from OFS.Folder import Folder
from zope.interface import Interface

from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PageTemplates.ZopePageTemplate import ZopePageTemplate

from Products.PluggableAuthService.interfaces.plugins import ILoginPasswordHostExtractionPlugin
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin
from Products.PluggableAuthService.interfaces.plugins import IRolesPlugin
from Products.PluggableAuthService.interfaces.plugins import IChallengePlugin
from Products.PluggableAuthService.interfaces.plugins import ICredentialsResetPlugin
from Products.PluggableAuthService.interfaces.plugins import IUserAdderPlugin
from Products.PluggableAuthService.interfaces.plugins import IUserEnumerationPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements

logger = logging.getLogger('ZMSPASSsoPlugin')

class IZMSPASSsoPlugin(Interface):
    """ Marker interface.
    """

manage_addZMSPASSsoPluginForm = PageTemplateFile(
    'www/zpdcapAdd', globals(), __name__='manage_addZMSPASSsoPluginForm')


def addZMSPASSsoPlugin( dispatcher
                       , id
                       , title=None
                       , header_name=''
                       , login_path=''
                       , REQUEST=None
                       ):
    """ Add a SSO Plugin to a Pluggable Auth Service. """
    sp = ZMSPASSsoPlugin(id, title, header_name, login_path)
    dispatcher._setObject(sp.getId(), sp)

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect( '%s/manage_workspace'
                                      '?manage_tabs_message='
                                      'ZMSPASSsoPluginr+added.'
                                    % dispatcher.absolute_url() )


class ZMSPASSsoPlugin(Folder, BasePlugin):
    """ Multi-plugin for managing details of SSO Authentication. """

    meta_type = 'ZMS PluggableAuthService SSO Plugin'
    zmi_icon = 'fas fa-cookie-bite text-danger'
    zmi_show_add_dialog = True
    header_name = '__ginger_snap'
    security = ClassSecurityInfo()
    SALT = "zms_auth:login"

    mock = PageTemplateFile('www/zpdcapMock', globals())

    _properties = ( { 'id'    : 'title'
                    , 'label' : 'Title'
                    , 'type'  : 'string'
                    , 'mode'  : 'w'
                    }
                  , { 'id'    : 'header_name'
                    , 'label' : 'Header Name'
                    , 'type'  : 'string'
                    , 'mode'  : 'w'
                    , 'default': 'HTTP_X_AUTH_RESULT'
                    }
                  , { 'id'     : 'secret_key'
                    , 'label'  : 'Secret Key'
                    , 'type'   : 'string'
                    , 'mode'   : 'w'
                    , 'default': ''
                    }
                  , { 'id'     : 'login_path'
                    , 'label'  : 'Login Path'
                    , 'type'   : 'string'
                    , 'mode'   : 'w'
                    , 'default': 'http://zms.hosting/auth/login'
                    }
                  , { 'id'     : 'came_from'
                    , 'label'  : 'Came From'
                    , 'type'   : 'string'
                    , 'mode'   : 'w'
                    , 'default': 'came_from'
                    }
                  )

    manage_options = ( BasePlugin.manage_options[:1]
                     + Folder.manage_options[:1]
                     + Folder.manage_options[2:]
                     )

    # Management Permissions.
    # -----------------------
    __viewPermissions__ = (
      'manage_page_header', 'manage_page_footer', 'manage_tabs'
      )
    __ac_permissions__=(
      ('View', __viewPermissions__),
      )

    def __init__(self, id, title=None, header_name='HTTP_X_AUTH_RESULT', login_path='http://zms.hosting/auth/login'):
        self._setId(id)
        self.title = title
        self.secret_key = ''
        self.header_name = header_name
        self.login_path = login_path
        self.came_from = 'came_from'


    def getSecretKey(self):
        from cryptography.fernet import Fernet
        if not getattr(self,'secret_key',''):
            self.secret_key = Fernet.generate_key()
        return self.secret_key
        
    
    def encryptToken(self, d):
        from itsdangerous import TimedSerializer
        coder = TimedSerializer(secret_key=self.getSecretKey(),salt=self.SALT)
        token = coder.dumps(d)
        return token


    def decryptToken(self, token, debug=False):
        try:
            from itsdangerous import TimedSerializer
            coder = TimedSerializer(secret_key=self.getSecretKey(),salt=self.SALT)
            if isinstance(token,str):
              token = bytes(token,'utf-8')
            d = coder.loads(token)
            return d
        except:
            import sys, traceback, string
            type, val, tb = sys.exc_info()
            msg = ''.join(traceback.format_exception(type, val, tb))
            sys.stderr.write(msg)
            del type, val, tb
            if debug:
              return msg
        return None


    security.declarePrivate('extractCredentials')
    def extractCredentials(self, request):
        """ Extract credentials from request. """
        token = request.get(self.header_name, '')
        decoded_token = self.decryptToken(token)
        if decoded_token:
            decoded_token['remote_host'] = request.get('REMOTE_HOST', '')
            try:
                decoded_token['remote_address'] = request.getClientAddr()
            except AttributeError:
                decoded_token['remote_address'] = request.get('REMOTE_ADDR', '')
        return decoded_token


    security.declarePrivate('challenge')
    def challenge(self, request, response, **kw):
        """ Challenge the user for credentials. """
        return self.unauthorized()


    #
    #    ICredentialsResetPlugin implementation
    #
    security.declarePrivate('resetCredentials')
    def resetCredentials(self, request, response):
        """ user has logged out.
        """
        # Hook for custom reset-credentials.
        try:
          self.customResetCredentials(request,response)
        except:
          logger.debug('can\'t customResetCredentials', exc_info=True)

        # Purge Data of Zope-Session.
        s = request.SESSION
        try:
          # using tempstorage
          s.invalidate()
        except:
          pass
        try:
          s = self.session_data_manager.getSessionData()
          s.clear()
          s.getBrowserIdManager().flushBrowserIdCookie()
        except:
          logger.debug('can\'t purge Data of Zope-Session', exc_info=True)
        
        # Clear Zope-Session.
        response.expireCookie("_ZopeId", path='/')


    security.declarePrivate('unauthorized')
    def unauthorized(self):
        request = self.REQUEST
        resp = request['RESPONSE']

        # Redirect if desired.
        url = self.getLoginURL()
        if url is not None:
            came_from = request.get('came_from', None)

            if came_from is None:
                came_from = request.get('ACTUAL_URL', '')
                query = request.get('QUERY_STRING')
                if query:
                    if not query.startswith('?'):
                        query = '?' + query
                    came_from = came_from + query
            else:
                # If came_from contains a value it means the user
                # must be coming through here a second time
                # Reasons could be typos when providing credentials
                # or a redirect loop (see below)
                req_url = request.get('ACTUAL_URL', '')

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

            token = request.get(self.header_name, '')
            decoded_token = self.decryptToken(token)
            if decoded_token is None:
                url = '%s%s%s=%s' % (url, sep, self.came_from, quote(came_from))
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


    #
    #    IAuthenticationPlugin implementation
    #
    security.declarePrivate( 'authenticateCredentials' )
    def authenticateCredentials( self, credentials, request=None ):
        """ See IAuthenticationPlugin.
        """
        request = self.REQUEST
        token = request.get(self.header_name, '')
        decoded_token = self.decryptToken(token)
        username = decoded_token['preferred_username'].split('@')[0]
        # Check valid-until against current timestamp.
        if 'valid_until' in decoded_token:
          valid_until = DateTime(creds['valid_until'])
          if valid_until.timeTime() < DateTime().timeTime():
              return None
        return (username, username)


    #
    #    IRolesPlugin implementation
    #
    security.declarePrivate( 'getRolesForPrincipal' )
    def getRolesForPrincipal( self, principal, request=None):
        """ See IRolesPlugin.
        """
        roles = []
        token = request.get(self.header_name, '')
        decoded_token = self.decryptToken(token)
        username = decoded_token['preferred_username'].split('@')[0]
        if principal.getId() == username and principal.getUserName() == username:
          roles.extend(decoded_token.get('roles',[]))
        return roles


    #
    #    IUserAdderPlugin implementation
    #
    security.declarePrivate( 'doAddUser' )
    def doAddUser(self, login, password):
        """ Add a user record to a User Manager, with the given login
            and password.  It is up to the implementation to determine
            if the login is used as user id as well.

        o Return a Boolean indicating whether a user was added or not
        """
        logins = getattr(self,'_logins',[])
        if login not in logins:
          logins.append(login)
          self._logins = logins
        return True


    #
    #    IUserEnumerationPlugin implementation
    #
    security.declarePrivate( 'enumerateUsers' )
    def enumerateUsers(self, id=None, login=None, exact_match=False, sort_by=None,
                       max_results=None, **kw):
        """ -> (user_info_1, ... user_info_N)

        o Return mappings for users matching the given criteria.

        o 'id' or 'login', in combination with 'exact_match' true, will
          return at most one mapping per supplied ID ('id' and 'login'
          may be sequences).

        o If 'exact_match' is False, then 'id' and / or login may be
          treated by the plugin as "contains" searches (more complicated
          searches may be supported by some plugins using other keyword
          arguments).

        o If 'sort_by' is passed, the results will be sorted accordingly.
          known valid values are 'id' and 'login' (some plugins may support
          others).

        o If 'max_results' is specified, it must be a positive integer,
          limiting the number of returned mappings.  If unspecified, the
          plugin should return mappings for all users satisfying the criteria.

        o Minimal keys in the returned mappings:

          'id' -- (required) the user ID, which may be different than
                  the login name

          'login' -- (required) the login name

          'pluginid' -- (required) the plugin ID (as returned by getId())

          'editurl' -- (optional) the URL to a page for updating the
                       mapping's user

        o Plugin *must* ignore unknown criteria.

        o Plugin may raise ValueError for invalid criteria.

        o Insufficiently-specified criteria may have catastrophic
          scaling issues for some implementations.
        """
        logins = getattr(self,'_logins',[])
        return [{'id':x,'login':x,'pluginid':self.getId()} for x in logins]


classImplements( ZMSPASSsoPlugin
               , IZMSPASSsoPlugin
               , ILoginPasswordHostExtractionPlugin
               , IAuthenticationPlugin
               , IRolesPlugin
               , IChallengePlugin
               , ICredentialsResetPlugin
               , IUserAdderPlugin
               , IUserEnumerationPlugin
               )

InitializeClass(ZMSPASSsoPlugin)