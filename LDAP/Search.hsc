{-# LANGUAGE TupleSections #-}
{- -*- Mode: haskell; -*-
Haskell LDAP Interface
Copyright (C) 2005 John Goerzen <jgoerzen@complete.org>

This code is under a 3-clause BSD license; see COPYING for details.
-}

{- |
   Module     : LDAP.Search
   Copyright  : Copyright (C) 2005 John Goerzen
   License    : BSD

   Maintainer : John Goerzen,
   Maintainer : jgoerzen\@complete.org
   Stability  : provisional
   Portability: portable

LDAP Searching

Written by John Goerzen, jgoerzen\@complete.org
-}

module LDAP.Search (SearchAttributes(..),
                    LDAPEntry(..), LDAPScope(..),
                    ldapSearch,
                    ldapSearchExt,
                    ldapParseResult
                   )
where

import LDAP.Control
import LDAP.Utils
import LDAP.Types
import LDAP.TypesLL
import LDAP.Data
import Foreign
import Foreign.C.String
#if (__GLASGOW_HASKELL__>=705)
import Foreign.C.Types(CInt(..))
#endif
import LDAP.Result
import Control.Exception(finally)
import Control.Monad ((<=<))

#include <ldap.h>
#include <sys/time.h>

{- | Defines what attributes to return with the search result. -}
data SearchAttributes =
   LDAPNoAttrs                   -- ^ No attributes
 | LDAPAllUserAttrs              -- ^ User attributes only
 | LDAPAttrList [String]         -- ^ User-specified list
   deriving (Eq, Show)

sa2sl :: SearchAttributes -> [String]
sa2sl LDAPNoAttrs = [ #{const_str LDAP_NO_ATTRS} ]
sa2sl LDAPAllUserAttrs = [ #{const_str LDAP_ALL_USER_ATTRIBUTES} ]
sa2sl (LDAPAttrList x) = x

data LDAPEntry = LDAPEntry 
    {ledn :: String             -- ^ Distinguished Name of this object
    ,leattrs :: [(String, [String])] -- ^ Mapping from attribute name to values
                           }
    deriving (Eq, Show)

data TimeVal = TimeVal
    {tvSec :: Int
    ,tvUSec :: Int
    } deriving Show

instance Storable TimeVal where
    sizeOf    _ = #{size struct timeval}
    alignment _ = #{alignment struct timeval}
    peek p = do
        sec <- peek (#{ptr struct timeval, tv_sec} p)
        usec <- peek (#{ptr struct timeval, tv_usec} p)
        return $ TimeVal { tvSec = sec, tvUSec = usec }
    poke p timeval = do
        poke (#{ptr struct timeval, tv_sec} p) $ tvSec timeval
        poke (#{ptr struct timeval, tv_usec} p) $ tvUSec timeval

ldapSearch :: LDAP              -- ^ LDAP connection object
           -> Maybe String      -- ^ Base DN for search, if any
           -> LDAPScope         -- ^ Scope of the search
           -> Maybe String      -- ^ Filter to be used (none if Nothing)
           -> SearchAttributes  -- ^ Desired attributes in result set
           -> Bool              -- ^ If True, exclude attribute values (return types only)
           -> IO [LDAPEntry]

ldapSearch ld base scope filter attrs attrsonly =
  withLDAPPtr ld (\cld ->
  withMString base (\cbase ->
  withMString filter (\cfilter ->
  withCStringArr0 (sa2sl attrs) (\cattrs ->
  do msgid <- checkLEn1 "ldapSearch" ld $
              ldap_search cld cbase (fromIntegral $ fromEnum scope)
                          cfilter cattrs (fromBool attrsonly)
     procSR ld cld msgid
                               )
                      )
                    )
                  )

ldapSearchExt :: LDAP             -- ^ LDAP connection object
              -> Maybe String     -- ^ Base DN for search, if any
              -> LDAPScope        -- ^ Scope of the search
              -> Maybe String     -- ^ Filter to be used (none if Nothing)
              -> SearchAttributes -- ^ Desired attributes in result set
              -> Bool             -- ^ If True, exclude attribute values (return types only)
              -> [LDAPControl]    -- ^ Specifies a list of LDAP server controls
              -> [LDAPControl]    -- ^ Specifies a list of LDAP server controls
              -> Maybe TimeVal    -- ^ The local search timeout value
              -> Int              -- ^ Specifies the maximum number of entries to return
              -> IO (LDAPMessage)
ldapSearchExt ld base scope filters attrs attrsonly serverctrls clientctrls timeout sizelimit =
    withLDAPPtr ld $ \cld ->
    withMString base $ \cbase ->
    withMString filters $ \cfilters ->
    withCStringArr0 (sa2sl attrs) $ \cattrs ->
    withArrayOfForeign0 nullPtr serverctrls $ \cserverctrls ->
    withArrayOfForeign0 nullPtr clientctrls $ \cclientctrls ->
    maybeWith with timeout $ \ctimeout ->
    alloca $ \cmsg -> do
        let cscope = fromIntegral $ fromEnum scope
            cattrsonly = fromBool attrsonly
            csizelimit = CInt $ fromIntegral sizelimit
        checkLE "ldapSearchExt" ld $
            ldap_search_ext_s cld cbase cscope cfilters cattrs cattrsonly
                cserverctrls cclientctrls ctimeout csizelimit cmsg
        newForeignPtr ldap_msgfree_call =<< checkNULL "ldapSearchExt" (peek cmsg)

ldapParseResult :: LDAP -> LDAPMessage -> IO ([LDAPEntry], [LDAPControl])
ldapParseResult ld msg =
    withLDAPPtr ld $ \cld ->
    withForeignPtr msg $ \cmsg ->
    alloca $ \cctrl -> do
        let cfreeit = fromBool False
        checkLE "ldapParseResult" ld $
            ldap_parse_result cld cmsg nullPtr nullPtr nullPtr nullPtr cctrl cfreeit
        ctrls <- traverse (newForeignPtr ldap_control_free) =<< peekArray0 nullPtr =<< peek cctrl
        (, ctrls) <$> procSRExt ld msg

procSR :: LDAP -> Ptr CLDAP -> LDAPInt -> IO [LDAPEntry]
procSR ld cld msgid =
  do res1 <- ldap_1result ld msgid
     --putStrLn "Have 1result"
     withForeignPtr res1 (\cres1 ->
      do felm <- ldap_first_entry cld cres1
         if felm == nullPtr
            then return []
            else do --putStrLn "Have first entry"
                    entry <- msg2Entry ld felm
                    next <- procSR ld cld msgid
                    --putStrLn $ "Next is " ++ (show next)
                    return $ entry:next
                         )

procSRExt :: LDAP -> ForeignPtr CLDAPMessage -> IO [LDAPEntry]
procSRExt ld msg =
    withLDAPPtr ld $ \cld ->
    withForeignPtr msg $
        go cld <=< ldap_first_entry cld
    where
        go cld felm
            | felm == nullPtr = return []
            | otherwise = do
                entry <- msg2Entry ld felm
                next <- go cld =<< ldap_next_entry cld felm
                pure $ entry:next

msg2Entry :: LDAP -> Ptr CLDAPMessage -> IO LDAPEntry
msg2Entry ld felm =
    withLDAPPtr ld $ \cld -> do
        cdn <- ldap_get_dn cld felm -- FIXME: check null
        dn <- peekCString cdn
        ldap_memfree cdn
        attrs <- getattrs ld felm
        return $ LDAPEntry {ledn = dn, leattrs = attrs}

data BerElement

getattrs :: LDAP -> (Ptr CLDAPMessage) -> IO [(String, [String])]
getattrs ld lmptr =
    withLDAPPtr ld (\cld -> alloca (f cld))
    where f cld (ptr::Ptr (Ptr BerElement)) =
              do cstr <- ldap_first_attribute cld lmptr ptr
                 if cstr == nullPtr
                    then return []
                    else do str <- peekCString cstr
                            ldap_memfree cstr
                            bptr <- peek ptr
                            values <- getvalues cld lmptr str
                            nextitems <- getnextitems cld lmptr bptr
                            return $ (str, values):nextitems

getnextitems :: Ptr CLDAP -> Ptr CLDAPMessage -> Ptr BerElement 
             -> IO [(String, [String])]
getnextitems cld lmptr bptr =
    do cstr <- ldap_next_attribute cld lmptr bptr
       if cstr == nullPtr
          then return []
          else do str <- peekCString cstr
                  ldap_memfree cstr
                  values <- getvalues cld lmptr str
                  nextitems <- getnextitems cld lmptr bptr
                  return $ (str, values):nextitems

getvalues :: LDAPPtr -> Ptr CLDAPMessage -> String -> IO [String]
getvalues cld clm attr =
    withCString attr (\cattr ->
    do berarr <- ldap_get_values_len cld clm cattr
       if berarr == nullPtr
            -- Work around bug between Fedora DS and OpenLDAP (ldapvi
            -- does the same thing)
            then return []
            else finally (procberarr berarr) (ldap_value_free_len berarr)
    )

procberarr :: Ptr (Ptr Berval) -> IO [String]
procberarr pbv =
    do bvl <- peekArray0 nullPtr pbv
       mapM bv2str bvl

foreign import ccall unsafe "ldap.h ldap_get_dn"
  ldap_get_dn :: LDAPPtr -> Ptr CLDAPMessage -> IO CString

foreign import ccall unsafe "ldap.h ldap_get_values_len"
  ldap_get_values_len :: LDAPPtr -> Ptr CLDAPMessage -> CString -> IO (Ptr (Ptr Berval))

foreign import ccall unsafe "ldap.h ldap_value_free_len"
  ldap_value_free_len :: Ptr (Ptr Berval) -> IO ()

foreign import ccall safe "ldap.h ldap_search"
  ldap_search :: LDAPPtr -> CString -> LDAPInt -> CString -> Ptr CString ->
                 LDAPInt -> IO LDAPInt

foreign import ccall safe "ldap.h ldap_search_ext_s"
  ldap_search_ext_s :: LDAPPtr -> CString -> LDAPInt -> CString -> Ptr CString ->
                       LDAPInt -> Ptr (Ptr CLDAPControl) -> Ptr (Ptr CLDAPControl) ->
                       Ptr TimeVal -> CInt -> Ptr (Ptr CLDAPMessage)-> IO LDAPInt

foreign import ccall unsafe "ldap.h ldap_first_entry"
  ldap_first_entry :: LDAPPtr -> Ptr CLDAPMessage -> IO (Ptr CLDAPMessage)

foreign import ccall unsafe "ldap.h ldap_next_entry"
  ldap_next_entry :: LDAPPtr -> Ptr CLDAPMessage -> IO (Ptr CLDAPMessage)

foreign import ccall unsafe "ldap.h ldap_first_attribute"
  ldap_first_attribute :: LDAPPtr -> Ptr CLDAPMessage -> Ptr (Ptr BerElement) 
                       -> IO CString

foreign import ccall unsafe "ldap.h ldap_next_attribute"
  ldap_next_attribute :: LDAPPtr -> Ptr CLDAPMessage -> Ptr BerElement
                       -> IO CString

foreign import ccall safe "ldap.h ldap_parse_result"
  ldap_parse_result :: LDAPPtr -> Ptr CLDAPMessage -> Ptr LDAPInt ->
                       Ptr (CString) -> Ptr (CString) -> Ptr (Ptr CString) ->
                       Ptr (Ptr (Ptr CLDAPControl)) -> LDAPInt -> IO LDAPInt

