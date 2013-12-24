# -*- encoding: utf-8 -*-

import os
import re

from M2Crypto import X509, ASN1, m2, RSA, BIO
import m2ext

def x509_ext_get_object(self):
    return ASN1.ASN1_Object(m2_ext.x509_extension_get_object(self._ptr()), 0)

def asn1_object_get_oid(self):
    return m2.obj_obj2txt(self._ptr(), 1)

def asn1_object_get_sn(self):
    return m2.obj_nid2sn(m2.obj_obj2nid(self._ptr()))

def x509_is_proxy(self):
    for i in xrange(self.get_ext_count()):
        ext = self.get_ext_at(i)
        ext_obj = x509_ext_get_object(ext)
        oid = asn1_object_get_oid(ext_obj)
        if oid == '1.3.6.1.5.5.7.1.14':
            return True
    return False

def rsa_to_der(rsa):
    buf = BIO.MemoryBuffer()
    rsa.save_key_der_bio(buf)
    return buf.getvalue()

def monkey():
    X509.X509_Extension.get_object = x509_ext_get_object
    ASN1.ASN1_Object.get_oid = asn1_object_get_oid
    ASN1.ASN1_Object.get_sn = asn1_object_get_sn
    X509.X509.is_proxy = x509_is_proxy
    RSA.RSA.as_der = rsa_to_der
