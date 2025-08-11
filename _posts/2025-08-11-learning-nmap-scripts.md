---
layout: post
title:  "Creating an Nmap Script"
date:   2025-08-11 11:00:00 +0100
categories: nmap tooling
description: Creating a custom nmap tool to validate plaintext FTP findings
---

While testing, I often come across FTP instances. While it is often employing the secure `FTPS`, sometimes cleartext FTP is still supported or only supported.

To help streamline testing, I wanted to create an nmap script which will be able to tell me about whether `FTPS` is not supported, supported, or required. I started by checking out the other nmap scripts, alongside [this tutorial](https://nmap.org/book/nse-tutorial.html)

{% highlight lua %}
local ftp = require "ftp"
local match = require "match"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Checks whether an FTP server supports TLS by sending AUTH TLS and reporting the response code.
Reports on 3 cases:
1. TLS Supported (not required)
2. TLS Supported (required)
3. TLS Unsupported
]]

author = "Adam Crease"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "auth", "safe"}

portrule = shortport.port_or_service({21,990}, {"ftp","ftps"})
{% endhighlight %}

Once I had the groundwork set up, I needed to define the basic checks that were going to be conducted. Firstly, I wanted to try and connect to the service and check whether the `AUTH TLS` command is accepted. If an error is thrown, we know that TLS isn't supported and life is easy. This can be done with the below logic.

{% highlight lua %}
try(socket:connect(host.ip, port.number))
status, response = socket:receive_lines(1)
if not status then return "FTP banner not received" end

socket:send("AUTH TLS\r\n")
status, response = socket:receive_lines(1)

socket:close()

local socket, code, message, buffer = ftp.connect(host, port, {request_timeout=8000})
if not socket then
 stdnse.debug1("Couldn't connect: %s", code or message)
 return nil
end
if code and code ~= 220 then
 stdnse.debug1("banner code %d %q.", code, message)
 return nil
end
local tls_supported = string.match(response, "234")
{% endhighlight %}

Secondly, if TLS is supported, we want to try logging in plaintext and check out if an error is thrown. From my testing, `530` will be thrown if there is an auth issue, TLS errors (such as requiring auth only over TLS) will be thrown as other error codes. This can be captured like below

{% highlight lua %}
if tls_supported then
 local status, code, message = ftp.auth(socket, buffer, "anonymous", "IEUser@")
 result = result .. "TLS Supported"
 if not tostring(code):match("^530") then
    result = result .. " (required)"
 else
    result = result .. " (not required)"
 end
else
 result = result .. "TLS Unsupported"
end
{% endhighlight %}

While these aren't perfect, they've been enough to check a couple different servers running locally with correct results, shown below.

{% highlight console %}
➜  ~ nmap localhost  -sCV --script "./ftp-tls-discovery.nse"
Starting Nmap 7.95 ( https://nmap.org )
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000021s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
23/tcp open  ftp     FileZilla ftpd 1.10.5
| ftp-tls-discovery: 
|_  TLS Supported (required)
{% endhighlight %}