# -*- coding: utf-8 -*- 
################################################################################
# ZMSPASRolePlugin.py
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
from Products.PluggableAuthService.interfaces.plugins import IRolesPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from Products.PythonScripts import PythonScript

class IZMSPASRolePlugin(Interface):
    """ Marker interface.
    """

manage_addZMSPASRolePluginForm = PageTemplateFile(
    'www/zprpAdd', globals(), __name__='manage_addZMSPASRolePluginForm' )

def addZMSPASRolePlugin( dispatcher, id, title='', RESPONSE=None ):
    """ Add a Local Role Plugin to 'dispatcher'.
    """

    rp = ZMSPASRolePlugin( id, title )
    dispatcher._setObject( id, rp )

    pysid = 'getRolesForPrincipalImpl'
    py = """## Script (Python) "'%s'"
##bind container=container
##bind context=context
##bind namespace=
##bind script=script
##bind subpath=traverse_subpath
##parameters=principal
##title=getRolesForPrincipal (implementation)
##
return None
"""%pysid
    PythonScript.manage_addPythonScript(rp,pysid)
    pys = getattr(rp,pysid)
    pys.write(py)

    if RESPONSE is not None:
        RESPONSE.redirect( '%s/manage_main?manage_tabs_message=%s' %
                           ( dispatcher.absolute_url()
                           , 'ZMSPASRolePlugin+added.' ) )

class ZMSPASRolePlugin( Folder, BasePlugin ):
    """ Provide roles.
    """

    meta_type = 'ZMS PluggableAuthService Role Plugin'
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
    #    IRolesPlugin implementation
    #
    security.declarePrivate( 'getRolesForPrincipal' )
    def getRolesForPrincipal( self, principal, request=None ):

        """ See IRolesPlugin.
        """
        pysid = 'getRolesForPrincipalImpl'
        pys = getattr(self,pysid,None)
        if pys is not None:
          return pys(principal=principal)
        return None

classImplements( ZMSPASRolePlugin
               , IZMSPASRolePlugin
               , IRolesPlugin
               )

InitializeClass( ZMSPASRolePlugin )
