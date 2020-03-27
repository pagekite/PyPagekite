"""
This is the main function for the Android version of PageKite.
"""
#############################################################################

from __future__ import absolute_import

LICENSE = """\
This file is part of pagekite.py.
Copyright 2010-2020, the Beanstalks Project ehf. and Bjarni Runar Einarsson

This program is free software: you can redistribute it and/or modify it under
the terms of the  GNU  Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,  but  WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see: <http://www.gnu.org/licenses/>
"""
#############################################################################
import sys
import pagekite.pk as pk
import pagekite.httpd as httpd


def Configure(pkobj):
  pkobj.rcfile = "/sdcard/pagekite.cfg"
  pkobj.enable_sslzlib = True
  pk.Configure(pkobj)

if __name__ == "__main__":
  if sys.stdout.isatty():
    import pagekite.ui.basic
    uiclass = pagekite.ui.basic.BasicUi
  else:
    uiclass = pk.NullUi

  pk.Main(pk.PageKite, Configure,
          uiclass=uiclass,
          http_handler=httpd.UiRequestHandler,
          http_server=httpd.UiHttpServer)

##############################################################################
CERTS="""\
StartCom Ltd.
=============
-----BEGIN CERTIFICATE-----
MIIFFjCCBH+gAwIBAgIBADANBgkqhkiG9w0BAQQFADCBsDELMAkGA1UEBhMCSUwxDzANBgNVBAgT
BklzcmFlbDEOMAwGA1UEBxMFRWlsYXQxFjAUBgNVBAoTDVN0YXJ0Q29tIEx0ZC4xGjAYBgNVBAsT
EUNBIEF1dGhvcml0eSBEZXAuMSkwJwYDVQQDEyBGcmVlIFNTTCBDZXJ0aWZpY2F0aW9uIEF1dGhv
cml0eTEhMB8GCSqGSIb3DQEJARYSYWRtaW5Ac3RhcnRjb20ub3JnMB4XDTA1MDMxNzE3Mzc0OFoX
DTM1MDMxMDE3Mzc0OFowgbAxCzAJBgNVBAYTAklMMQ8wDQYDVQQIEwZJc3JhZWwxDjAMBgNVBAcT
BUVpbGF0MRYwFAYDVQQKEw1TdGFydENvbSBMdGQuMRowGAYDVQQLExFDQSBBdXRob3JpdHkgRGVw
LjEpMCcGA1UEAxMgRnJlZSBTU0wgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxITAfBgkqhkiG9w0B
CQEWEmFkbWluQHN0YXJ0Y29tLm9yZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA7YRgACOe
yEpRKSfeOqE5tWmrCbIvNP1h3D3TsM+x18LEwrHkllbEvqoUDufMOlDIOmKdw6OsWXuO7lUaHEe+
o5c5s7XvIywI6Nivcy+5yYPo7QAPyHWlLzRMGOh2iCNJitu27Wjaw7ViKUylS7eYtAkUEKD4/mJ2
IhULpNYILzUCAwEAAaOCAjwwggI4MA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgHmMB0GA1Ud
DgQWBBQcicOWzL3+MtUNjIExtpidjShkjTCB3QYDVR0jBIHVMIHSgBQcicOWzL3+MtUNjIExtpid
jShkjaGBtqSBszCBsDELMAkGA1UEBhMCSUwxDzANBgNVBAgTBklzcmFlbDEOMAwGA1UEBxMFRWls
YXQxFjAUBgNVBAoTDVN0YXJ0Q29tIEx0ZC4xGjAYBgNVBAsTEUNBIEF1dGhvcml0eSBEZXAuMSkw
JwYDVQQDEyBGcmVlIFNTTCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEhMB8GCSqGSIb3DQEJARYS
YWRtaW5Ac3RhcnRjb20ub3JnggEAMB0GA1UdEQQWMBSBEmFkbWluQHN0YXJ0Y29tLm9yZzAdBgNV
HRIEFjAUgRJhZG1pbkBzdGFydGNvbS5vcmcwEQYJYIZIAYb4QgEBBAQDAgAHMC8GCWCGSAGG+EIB
DQQiFiBGcmVlIFNTTCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAyBglghkgBhvhCAQQEJRYjaHR0
cDovL2NlcnQuc3RhcnRjb20ub3JnL2NhLWNybC5jcmwwKAYJYIZIAYb4QgECBBsWGWh0dHA6Ly9j
ZXJ0LnN0YXJ0Y29tLm9yZy8wOQYJYIZIAYb4QgEIBCwWKmh0dHA6Ly9jZXJ0LnN0YXJ0Y29tLm9y
Zy9pbmRleC5waHA/YXBwPTExMTANBgkqhkiG9w0BAQQFAAOBgQBscSXhnjSRIe/bbL0BCFaPiNhB
OlP1ct8nV0t2hPdopP7rPwl+KLhX6h/BquL/lp9JmeaylXOWxkjHXo0Hclb4g4+fd68p00UOpO6w
NnQt8M2YI3s3S9r+UZjEHjQ8iP2ZO1CnwYszx8JSFhKVU2Ui77qLzmLbcCOxgN8aIDjnfg==
-----END CERTIFICATE-----

StartCom Certification Authority
================================
-----BEGIN CERTIFICATE-----
MIIHyTCCBbGgAwIBAgIBATANBgkqhkiG9w0BAQUFADB9MQswCQYDVQQGEwJJTDEWMBQGA1UEChMN
U3RhcnRDb20gTHRkLjErMCkGA1UECxMiU2VjdXJlIERpZ2l0YWwgQ2VydGlmaWNhdGUgU2lnbmlu
ZzEpMCcGA1UEAxMgU3RhcnRDb20gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMDYwOTE3MTk0
NjM2WhcNMzYwOTE3MTk0NjM2WjB9MQswCQYDVQQGEwJJTDEWMBQGA1UEChMNU3RhcnRDb20gTHRk
LjErMCkGA1UECxMiU2VjdXJlIERpZ2l0YWwgQ2VydGlmaWNhdGUgU2lnbmluZzEpMCcGA1UEAxMg
U3RhcnRDb20gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
ggIKAoICAQDBiNsJvGxGfHiflXu1M5DycmLWwTYgIiRezul38kMKogZkpMyONvg45iPwbm2xPN1y
o4UcodM9tDMr0y+v/uqwQVlntsQGfQqedIXWeUyAN3rfOQVSWff0G0ZDpNKFhdLDcfN1YjS6LIp/
Ho/u7TTQEceWzVI9ujPW3U3eCztKS5/CJi/6tRYccjV3yjxd5srhJosaNnZcAdt0FCX+7bWgiA/d
eMotHweXMAEtcnn6RtYTKqi5pquDSR3l8u/d5AGOGAqPY1MWhWKpDhk6zLVmpsJrdAfkK+F2PrRt
2PZE4XNiHzvEvqBTViVsUQn3qqvKv3b9bZvzndu/PWa8DFaqr5hIlTpL36dYUNk4dalb6kMMAv+Z
6+hsTXBbKWWc3apdzK8BMewM69KN6Oqce+Zu9ydmDBpI125C4z/eIT574Q1w+2OqqGwaVLRcJXrJ
osmLFqa7LH4XXgVNWG4SHQHuEhANxjJ/GP/89PrNbpHoNkm+Gkhpi8KWTRoSsmkXwQqQ1vp5Iki/
untp+HDH+no32NgN0nZPV/+Qt+OR0t3vwmC3Zzrd/qqc8NSLf3Iizsafl7b4r4qgEKjZ+xjGtrVc
UjyJthkqcwEKDwOzEmDyei+B26Nu/yYwl/WL3YlXtq09s68rxbd2AvCl1iuahhQqcvbjM4xdCUsT
37uMdBNSSwIDAQABo4ICUjCCAk4wDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAa4wHQYDVR0OBBYE
FE4L7xqkQFulF2mHMMo0aEPQQa7yMGQGA1UdHwRdMFswLKAqoCiGJmh0dHA6Ly9jZXJ0LnN0YXJ0
Y29tLm9yZy9zZnNjYS1jcmwuY3JsMCugKaAnhiVodHRwOi8vY3JsLnN0YXJ0Y29tLm9yZy9zZnNj
YS1jcmwuY3JsMIIBXQYDVR0gBIIBVDCCAVAwggFMBgsrBgEEAYG1NwEBATCCATswLwYIKwYBBQUH
AgEWI2h0dHA6Ly9jZXJ0LnN0YXJ0Y29tLm9yZy9wb2xpY3kucGRmMDUGCCsGAQUFBwIBFilodHRw
Oi8vY2VydC5zdGFydGNvbS5vcmcvaW50ZXJtZWRpYXRlLnBkZjCB0AYIKwYBBQUHAgIwgcMwJxYg
U3RhcnQgQ29tbWVyY2lhbCAoU3RhcnRDb20pIEx0ZC4wAwIBARqBl0xpbWl0ZWQgTGlhYmlsaXR5
LCByZWFkIHRoZSBzZWN0aW9uICpMZWdhbCBMaW1pdGF0aW9ucyogb2YgdGhlIFN0YXJ0Q29tIENl
cnRpZmljYXRpb24gQXV0aG9yaXR5IFBvbGljeSBhdmFpbGFibGUgYXQgaHR0cDovL2NlcnQuc3Rh
cnRjb20ub3JnL3BvbGljeS5wZGYwEQYJYIZIAYb4QgEBBAQDAgAHMDgGCWCGSAGG+EIBDQQrFilT
dGFydENvbSBGcmVlIFNTTCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTANBgkqhkiG9w0BAQUFAAOC
AgEAFmyZ9GYMNPXQhV59CuzaEE44HF7fpiUFS5Eyweg78T3dRAlbB0mKKctmArexmvclmAk8jhvh
3TaHK0u7aNM5Zj2gJsfyOZEdUauCe37Vzlrk4gNXcGmXCPleWKYK34wGmkUWFjgKXlf2Ysd6AgXm
vB618p70qSmD+LIU424oh0TDkBreOKk8rENNZEXO3SipXPJzewT4F+irsfMuXGRuczE6Eri8sxHk
fY+BUZo7jYn0TZNmezwD7dOaHZrzZVD1oNB1ny+v8OqCQ5j4aZyJecRDjkZy42Q2Eq/3JR44iZB3
fsNrarnDy0RLrHiQi+fHLB5LEUTINFInzQpdn4XBidUaePKVEFMy3YCEZnXZtWgo+2EuvoSoOMCZ
EoalHmdkrQYuL6lwhceWD3yJZfWOQ1QOq92lgDmUYMA0yZZwLKMS9R9Ie70cfmu3nZD0Ijuu+Pwq
yvqCUqDvr0tVk+vBtfAii6w0TiYiBKGHLHVKt+V9E9e4DGTANtLJL4YSjCMJwRuCO3NJo2pXh5Tl
1njFmUNj403gdy3hZZlyaQQaRwnmDwFWJPsfvw55qVguucQJAX6Vum0ABj6y6koQOdjQK/W/7HW/
lwLFCRsI3FU34oH7N4RDYiDK51ZLZer+bMEkkyShNOsF/5oirpt9P/FlUQqmMGqz9IgcgA38coro
g14=
-----END CERTIFICATE-----
"""
