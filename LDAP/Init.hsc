{- -*- Mode: haskell; -*-
Haskell CDK Interface
Copyright (C) 2005 John Goerzen <jgoerzen@complete.org>

This code is under a 3-clause BSD license; see COPYING for details.
-}

{- |
   Module     : CDK.Init
   Copyright  : Copyright (C) 2005 John Goerzen
   License    : BSD

   Maintainer : John Goerzen,
   Maintainer : jgoerzen@complete.org
   Stability  : provisional
   Portability: portable

Initialization and shutdown for LDAP programs

Written by John Goerzen, jgoerzen\@complete.org
-}

module LDAP.Init(ldap_open,
                 ldap_init)
where

import Foreign.Ptr
import Foreign.C.String
import LDAP.Types
import Foreign.C.Types

{- | Preferred way to initialize a LDAP connection. -}
ldap_init :: String -> CInt -> IO LDAP
ldap_init host port =
    withCString host (\cs ->
       cldap_init cs port)

ldap_open :: String -> CInt -> IO LDAP
ldap_open host port =
    withCString host (\cs ->
                      cldap_open cs port)

foreign import ccall unsafe "ldap.h ldap_init"
  cldap_init :: CString -> CInt -> IO LDAP


foreign import ccall unsafe "ldap.h ldap_open"
  cldap_open :: CString -> CInt -> IO LDAP


