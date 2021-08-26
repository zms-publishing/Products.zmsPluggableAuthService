# -*- coding: utf-8 -*- 
################################################################################
# ZMSPASUserPlugin.py
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
from __future__ import absolute_import
from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass
from zope.interface import Interface
from OFS.Folder import Folder
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin
from Products.PluggableAuthService.interfaces.plugins import IUserEnumerationPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from Products.PythonScripts import PythonScript

class IZMSPASUserPlugin(Interface):
    """ Marker interface.
    """

manage_addZMSPASUserPluginForm = PageTemplateFile(
    'www/zpupAdd', globals(), __name__='manage_addZMSPASUserPluginForm' )

def addZMSPASUserPlugin( dispatcher, id, title='', RESPONSE=None ):
    """ Add a Local User Plugin to 'dispatcher'.
    """

    rp = ZMSPASUserPlugin( id, title )
    dispatcher._setObject( id, rp )

    pysid = 'enumerateUsersImpl'
    py = """## Script (Python) "'%s'"
##bind container=container
##bind context=context
##bind namespace=
##bind script=script
##bind subpath=traverse_subpath
##parameters=id=None, login=None, exact_match=False, sort_by=None, max_results=None
##title=enumerateUsers (implementation)
##
user_info = []
user_ids = []
plugin_id = self.getId()
e_url = self.getId()+'/manage_users'
for user_id in ['test']:
  qs = 'user_id='+user_id
  info = { 'id' : user_id
       , 'login' : user_id
       , 'pluginid' : plugin_id
       , 'editurl' : e_url+'?'+qs
       }
  user_info.append( info )
return tuple(user_info)
"""%pysid
    PythonScript.manage_addPythonScript(rp,pysid)
    pys = getattr(rp,pysid)
    pys.write(py)

    pysid = 'authenticateCredentialsImpl'
    py = """## Script (Python) "'%s'"
##bind container=container
##bind context=context
##bind namespace=
##bind script=script
##bind subpath=traverse_subpath
##parameters=credentials
##title=authenticateCredentials (implementation)
##
login = credentials.get( 'login' )
password = credentials.get( 'password' )
if login is None or password is None:
  return None
userid = login
return userid, login
"""%pysid
    PythonScript.manage_addPythonScript(rp,pysid)
    pys = getattr(rp,pysid)
    pys.write(py)

    if RESPONSE is not None:
        RESPONSE.redirect( '%s/manage_main?manage_tabs_message=%s' %
                           ( dispatcher.absolute_url()
                           , 'ZMSPASUserPlugin+added.' ) )

class ZMSPASUserPlugin( Folder, BasePlugin ):
    """ Provide roles.
    """

    meta_type = 'ZMS PluggableAuthService User Plugin'
    zmi_icon = 'fas fa-user'
    zmi_show_add_dialog = True
    security = ClassSecurityInfo()

    manage_options = ( BasePlugin.manage_options[:1]
                     + Folder.manage_options[:1]
                     + Folder.manage_options[2:]
                     )

    _properties = BasePlugin._properties + Folder._properties

    def __init__( self, id, title=None ):
        self._setId( id )
        self.title = title

    #
    #    IUserEnumerationPlugin implementation
    #
    security.declarePrivate( 'enumerateUsers' )
    def enumerateUsers( self
                      , id=None
                      , login=None
                      , exact_match=False
                      , sort_by=None
                      , max_results=None
                      , **kw
                      ):

        """ See IUserEnumerationPlugin.
        """
        pysid = 'enumerateUsersImpl'
        pys = getattr(self,pysid,None)
        if pys is not None:
          return pys(id=id,login=login,exact_match=exact_match,sort_by=sort_by,max_results=max_results)
        return None


    #
    #    IAuthenticationPlugin implementation
    #
    security.declarePrivate( 'authenticateCredentials' )
    def authenticateCredentials( self, credentials, request=None ):

        """ See IAuthenticationPlugin.
        """
        auth = None
        pysid = 'authenticateCredentialsImpl'
        pys = getattr(self,pysid,None)
        if pys is not None:
          auth = pys(credentials=credentials)
        return auth

classImplements( ZMSPASUserPlugin
               , IZMSPASUserPlugin
               , IAuthenticationPlugin
               , IUserEnumerationPlugin
               )

InitializeClass( ZMSPASUserPlugin )
