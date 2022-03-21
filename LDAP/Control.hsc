module LDAP.Control (LDAPControl,
                     CLDAPControl,
                     LDAPCookie,
                     ldapCreatePageControl,
                     ldapParsePageControl,
                     ldap_control_free
                    )
where

#include <ldap.h>

import LDAP.Utils
import LDAP.Types
import LDAP.TypesLL
import Foreign
import Foreign.C.Types

data CLDAPControl
type LDAPControl = ForeignPtr CLDAPControl

type LDAPCookie = ForeignPtr Berval

ldapCreatePageControl :: LDAP             -- ^ LDAP connection object
                      -> Int              -- ^ Page Size
                      -> Maybe LDAPCookie -- ^ Cookie
                      -> Bool             -- ^ Specifies the criticality of paged results on the search
                      -> IO (LDAPControl)
ldapCreatePageControl ld count cookie critical =
    withLDAPPtr ld $ \cld ->
    maybeWith withForeignPtr cookie $ \ccookie ->
    alloca $ \ccontrol -> do
        let ccount = fromIntegral count
            ccritical = fromBool critical
        checkLE "ldapCreatePageControl" ld $
            ldap_create_page_control cld ccount ccookie ccritical ccontrol
        newForeignPtr ldap_control_free =<< peek ccontrol

ldapParsePageControl :: LDAP -> [LDAPControl] -> IO (Maybe LDAPCookie)
ldapParsePageControl ld ctrls =
    withLDAPPtr ld $ \cld ->
    withArrayOfForeign0 nullPtr ctrls $ \cctrls ->
    alloca $ \ccookie -> do
        checkLE "ldapParsePageControl" ld $
            ldap_parse_page_control cld cctrls nullPtr ccookie
        cookie <- newForeignPtr ldap_memfree_call =<< peek ccookie
        withForeignPtr cookie $ \pcookie -> do
            str <- bv2str pcookie
            pure $ case str of
                       "" -> Nothing
                       _ -> Just cookie

foreign import ccall safe "ldap.h ldap_create_page_control"
  ldap_create_page_control :: LDAPPtr -> BERInt -> Ptr Berval -> LDAPInt ->
                              Ptr (Ptr CLDAPControl) -> IO LDAPInt

foreign import ccall safe "ldap.h &ldap_control_free"
  ldap_control_free :: FunPtr (Ptr CLDAPControl -> IO ())

foreign import ccall safe "ldap.h ldap_parse_page_control"
  ldap_parse_page_control :: LDAPPtr -> Ptr (Ptr CLDAPControl) -> Ptr (BERInt) ->
                             Ptr (Ptr Berval) -> IO LDAPInt

foreign import ccall unsafe "ldap.h &ldap_memfree"
  ldap_memfree_call :: FunPtr (Ptr Berval -> IO ())
