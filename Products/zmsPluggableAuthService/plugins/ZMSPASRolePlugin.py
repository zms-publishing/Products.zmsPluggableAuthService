##############################################################################
#
# Copyright (c) 2001 Zope Corporation and Contributors. All Rights
# Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this
# distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################

from __future__ import absolute_import
import six
from AccessControl.SecurityInfo import ClassSecurityInfo
from AccessControl.Permissions import view
from AccessControl.class_init import InitializeClass
from OFS.Folder import Folder

from zope.interface import Interface

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
