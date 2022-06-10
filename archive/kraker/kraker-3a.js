/*
Local Proxy Server for Alleycat Player

Improvements from version 1c to version 2a:

- handle double-slash at start of "location" response header
- handle rare case where "?" immediately follows host name without a slash
- do not strip byte-range headers in non-passthrough mode (problem with seeking on mp4 videos)
- handle socket disconnection error (ECONNRESET) in default_handler (crash issue)
- handle ".well-known/http-opportunistic" request coming from Firefox for 123tvnow.com streams
- delete request headers "origin" and "referer" if set to blank
- complete rewrite of local GET and PUT; security model via _aliases.txt

Improvements from version 2a to version 2b:

- added gzip decompression for m3u8 handler
- added ability to replace response headers (indicated with "!")
- added crash check in case SSL files are missing
- added Socks5 proxy server for DNS and TOR support

Improvements from version 2b to version 2c:

- updated init_settings to not invoke DNS "default" on reload
- updated proxy_handler to correctly destroy sockets (memory leak)
- added reporting system to track socket disposition
- added dns_lookup in http_handler and proxy_handler

Improvements from version 2c to version 3a:

- updated dns_lookup to report timing and IP address
- updated dns_lookup to handle four simultaneous lookups
- updated http_handler to destroy network connection (memory leak)
- added special cases "LOCAL" and "0.0.0.0"
- added DNS over HTTPS (JSON format only)

*/

const fs    = require ('fs');
const http  = require ('http');
const https = require ('https');
const zlib  = require ('zlib');

// for proxy tunnel
const net   = require ('net');
const dns   = require ('dns');

var aliases = "_aliases.txt", settings = "_settings.txt";

var http_port = 8080, https_port = 8081, socks_port = 8088;
var tor1_port = 9050, tor2_port = 9150;

var proxy_name = "Kraker-3a", proxy_host = "http://localhost:" + http_port + "/";

var reqcount = passthru = last_time = 0, last_pass = "", local_files = [];

var mime_list = {
  txt: "text/plain", htm: "text/html", html: "text/html", js: "application/javascript", json: "application/json",
  gif: "image/gif", jpeg: "image/jpeg", jpg: "image/jpeg", png: "image/png", mp3: "audio/mpeg", mp4: "video/mp4",
  webm: "video/webm", mpd: "application/dash+xml", m3u8: "application/x-mpegurl", ts: "video/mp2t"
};

var ssl_key = null; try { ssl_key = fs.readFileSync ("_https_key.pem"); } catch(e) {};
var ssl_crt = null; try { ssl_crt = fs.readFileSync ("_https_crt.pem"); } catch(e) {};

var ssl = { key: ssl_key, cert: ssl_crt, requestCert: false, rejectUnauthorized: false };

http.createServer (http_handler).listen (http_port);
https.createServer (ssl, https_handler).listen (https_port);

console.log ("=-----------------------------------------------------------------------------=");
console.log (" Kraker (version 3a) Local Proxy Server - waiting on port " + http_port + ", ctrl-C to exit ");
console.log ("=-----------------------------------------------------------------------------=");

var proxy_tunnel = null, proxy_flags = profile_count = -1, server = [], profile = [], dnslist = [];
var sockets_open = 0, sockets_count = 9, dns_count = 0, doh_address = doh_host = doh_path = "";

if (profile_count < 0)
{
  proxy_tunnel = net.createServer (proxy_handler).listen (socks_port);
  console.log (">> Commands list: activate, dnslookup, flags, reload, servers");
  console.log (">> " + init_settings (settings) + " (" + settings + ")");
}

///// End of Setup /////

///////////////////////////////////
///// function: init_settings /////
///////////////////////////////////

function init_settings (name)
{
  var i, j, k, data, sub, msg = "Settings file: ";

  if (!name || name.search (":|/") >= 0) return (msg + "INVALID NAME");
  data = fs.existsSync (name) ? fs.readFileSync (name, "utf8") : "";
  if (!data) return (msg + "NOT FOUND");

  profile_count++; server = []; profile = [];
  if ((i = data.indexOf ("$end$")) >= 0) data = data.substr (0, i);

  for (i = k = 0; (j = data.indexOf ("[", i) + 1) > 0; i = j)
  {
    if (j < k) return (msg + "ERROR"); k = data.indexOf ("]", j);
    sub = data.substr (j, k - j).replace (/\s+/gm, " ").trimEnd();
    if (sub.length > 5 && !sub.search ("#|\\?|\\+")) profile.push (sub);
  }

  if (proxy_flags < 0) dns_servers ("default"); add_resolver ("");

  if (proxy_flags < 0 || data.includes ("$fmodify=1$"))
  {
    proxy_flags = 0;
    if (data.includes ("$console=1$")) proxy_flags |= 1;
    if (data.includes ("$altport=1$")) proxy_flags |= 2;
    if (data.includes ("$tor4all=1$")) proxy_flags |= 4;
  }

  return (msg + "parsed and loaded");
}

//////////////////////////////////
///// function: add_resolver /////
//////////////////////////////////

function add_resolver (name)
{
  var i, j, k, p, q, r, s, data, sub;

  for (i = 0; i < profile.length; i++)
  {
    data = profile[i].split (" ");
    if (data.length < 2 || data[0] != "?" + name) continue;
    sub = data[1].split ("|");

    for (j = 0; j < sub.length; j++) if (p = sub[j])
    {
      if (server.includes (p)) for (k = 0; k < server.length; k += 2)
        if (p == server[k]) { server.splice (k, 2); break; }

      if (data.length < 3) q = ""; else
      {
        q = data [Math.trunc (Math.random() * (data.length - 2)) + 2];

        if (q[0] == "+") for (k = 0, s = q + " ", q = ""; k < profile.length; k++)
        {
          if (profile[k].indexOf (s)) continue;
          r = (profile[k]).split(" "); if (r.length < 2) continue;
          q = r [Math.trunc (Math.random() * (r.length - 1)) + 1];
          break;
        }
      }
      server.push (p); server.push (q == "TOR" || q == "LOCAL" || net.isIP (q) ? q : "");
    }
  }
}

//////////////////////////////////
///// function: init_servers /////
//////////////////////////////////

function init_servers ()
{
  var i, j = k = 0;

  for (i = 1; i < server.length; i += 2) if (server[i]) j++; else k++;
  console.log (">> + " + j); for (i = 0; i < server.length; i += 2) init_lookup (i);
  console.log (">> - " + k); return (j + " " + k);
}

function init_lookup (num)
{
  var name = server [num], ip = server [num + 1], count = profile_count;

  if (ip) { console.log (">> " + name + " [" + ip + "]"); return; }

  dns.resolve4 (name, function (err, list)
  {
    if (err || !list.length) console.log (">> DNS (failure) " + name); else
    {
      ip = list [Math.trunc (Math.random() * addr.length)];
      if (count != profile_count) ip = "CANCEL"; else server [num + 1] = ip;
      console.log (">> DNS (success) " + name + " [" + ip + "]");
    }
  });
}

/////////////////////////////////
///// function: dns_servers /////
/////////////////////////////////

function dns_servers (name)
{
  var n, s, t; if (dns_count && name) return ([]);

  if (name) doh_address = ""; if (!this.original) this.original = dns.getServers();

  if (name == "reset") dns.setServers (this.original); else if (name)
  {
    for (n = 0, s = "#" + name + " "; n < profile.length; n++)
    {
      t = profile [n]; if (t.indexOf (s)) continue;
      s = t.substr (s.length); s = s.split (" ");

      if (s.length > 1 && s[1].includes ("/"))
      {
        if (!net.isIP (s[0])) break; doh_address = s[0]; s = s[1].split ("/"); 
        doh_host = s[0]; doh_path = "/" + s[1] + "?type=A&name=";
      }
      else try { dns.setServers (s); } catch (e) { };

      name = ""; break;
    }

    if (name == "default") dns.setServers (this.original);
  }

  return dns.getServers();
}

/////////////////////////////////
///// function: dns_resolve /////
/////////////////////////////////

function dns_resolve (name)
{
  var ip = tor_resolve (name); return ((ip && ip != "TOR") ? ip : name);
}

/////////////////////////////////
///// function: tor_resolve /////
/////////////////////////////////

function tor_resolve (name)
{
  var n, p, ip = "";

  if (server.includes (name)) for (n = 0; n < server.length; n += 2)
    if (name == server [n] && (ip = server [n + 1])) break;

  if (!ip && (n = name.lastIndexOf (".")) > 0 && name.substr (n) == ".onion") ip = "TOR";

  return (ip ? ip : name);
}

////////////////////////////////
///// function: dns_lookup /////
////////////////////////////////

function dns_lookup (name, func)
{
  var m, n, s, t, p, q = name; if (q == "LOCAL") { func (""); return; }

  if (q == "TOR" || q == "localhost" || net.isIP (q)) { func (q); return; }

  if (!dns_count)
  {
    time_now = Math.trunc (Date.now() / 1000);
    if (dnslist.length > 150) dnslist.splice (0, 10);
  }

  for (n = dnslist.length - 2; n >= 0; n -= 2) if (q == dnslist [n])
  {
    p = dnslist [n + 1].split (" ");
    q = p [0]; t = time_now - (dns_count ? 300 : 0);
    if (p [1] * 1 < t) break; else { func (q); return; }
  }

  if (!q || dns_count > 3) setTimeout (function () { dns_lookup (name, func); }, 150); else
  {
    dns_count++; dnslist.push (name); dnslist.push (" ");
    n = dnslist.length - 1; p = Date.now();

    dns_master (name, function (err, addr, ttl)
    {
      t = Date.now(); if ((p = t - p) < 15) p = 15; t = Math.trunc (t / 1000);
      if (err) m = err; else { m = q = addr; name += " (" + ttl + "s)"; }
      s = "<< " + (doh_address ? "DOH" : "DNS") + ": ";

      if (err || proxy_flags & 17) console.log (s + p + "ms - " + m + " - " + name);
      dnslist [n] = q + " " + (t + (err ? 60 : 300)); dns_count--; func (q);
    });
  }
}

function dns_master (name, func)
{
  if (!doh_address)
  {
    dns.resolve4 (name, { ttl:true }, function (err, list)
    {
      if (err) func (err.code); else
        if (!list.length) func ("BLANK"); else func ("", list[0].address, list[0].ttl);
    });
    return;
  }

  var ans = "", i = j = k = 0;

  var options = {
    hostname: doh_address, port: 443, path: doh_path + name,
    headers: { host: doh_host, accept: 'application/dns-json', connection: 'keep-alive' },
    requestCert: false, rejectUnauthorized: false
  }

  var doh = https.get (options, function (res)
  {
    res.on ("data", function (d)
    {
      if (ans.length < 10000) ans = ans + d.toString();
    });

    res.on ("end", function ()
    {
      try {
        ans = JSON.parse (ans); k = ans.Status; ans = ans.Answer;
        if (k == undefined) k = -1; if (k == 0) i = ans.length; } catch(e) {}

      for (; i > 0; i--) if (ans[i-1].type == 1)
      {
        ans = ans[i-1]; i = ans.data; if (!(j = ans.TTL)) j = 0; break;
      }
      doh.destroy(); if (!i) func ("DNSERR(" + k + ")"); else func ("", i, j);
    });
  });

  doh.on ("error", function (err) { doh.destroy(); func (err.code); });
}

/////////////////////////////////////
///// function: default_handler /////
/////////////////////////////////////

function default_handler (response, error, local)
{
  var msg, err_msg, header = {};

  if (response._header)  // socket error while streaming
  {
    if (local) console.log ("--Unexpected disconnection--"); return;
  }

  msg = proxy_tunnel ? "active" : "closed";

  msg = "--------------------\n" +
        " Local Proxy Server \n" +
        "--------------------\n\n" +
        "Version Name: " + proxy_name + " [May 8, 2021]\n\n" +
        "HTTP at " + http_port + " (active), HTTPS at " + https_port + " (stub)\n" +
        "Socks5 Tunnel Proxy Server at " + socks_port + " (" + msg + ")\n\n" +
        "NODE.JS " + process.version + "\n";

  if (!error) error = 200; else
  {
    msg = "--Service Not Available--";
    if (error == "777") msg = " Local Request: Error";
    if (error == "888") msg = " Local Request: Invalid";
    if (error == "999") msg = "--Invalid Request--";
    if (local > 0) console.log (msg); msg = "";
  }

  if (error == 200) err_msg = "OK";
  if (error != 200) err_msg = "Deep State";
  if (error == 666) err_msg = "Illuminati";
  if (error == 999) err_msg = "Think Mirror";

  header ["content-type"] = "text/plain";
  header ["content-length"] = msg.length;
  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";

  response.writeHead (error, err_msg, header);
  response.end (msg);
}

//////////////////////////////////
///// function: options_proc /////
//////////////////////////////////

function options_proc (request, response, local)
{
  var header = {};

  var headers = request.headers ["access-control-request-headers"];
  var methods = request.headers ["access-control-request-method"];

  if (!headers || (headers != "accept" && headers != "range")) return false;

  if (headers) header ["access-control-allow-headers"] = headers;
  if (methods) header ["access-control-allow-methods"] = methods;

  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";
  header ["access-control-max-age"] = "30";
  header ["content-length"] = "0";

  response.writeHead (200, "OK", header);
  response.end ();
  return true;
}

///////////////////////////////
///// function: proc_done /////
///////////////////////////////

function proc_done (response, data, mime, local)
{
  var header = {};
  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";
  header ["access-control-allow-headers"] = "range";
  header ["access-control-expose-headers"] = "content-length, content-range, content-type";
  header ["accept-ranges"] = "bytes";

  if (mime) header ["content-type"] = mime;
  if (mime.substr (0,5) != "text/") header ["cache-control"] = "no-store";

  if (local > 0) console.log (" Local Request: OK");

  if (typeof (data) != "object")
  {
    header ["content-length"] = data.length;
    response.writeHead (200, "OK", header);
    response.end (data);
    return;
  }

  var size = data[0], start = data[1], end = data[2];
  header ["content-length"] = end - start + 1;

  if (size <= 0) response.writeHead (200, "OK", header); else
  {
    header ["content-range"] = "bytes " + start + "-" + end + "/" + size;
    response.writeHead (206, "Partial Content", header);
  }
}

///////////////////////////////
///// function: mime_type /////
///////////////////////////////

function mime_type (url)
{
  var u = url.split ("."), n = u.length - 1; if (n < 0) return ("");
  var mime = mime_list [u[n]]; return (mime ? mime : "");
}

////////////////////////////////
///// function: local_data /////
////////////////////////////////

function local_data (name, data)
{
  if (name) if (data)
  {
    for (var n = local_files.length - 1; n >= 0; n--)
      if (local_files [n]['name'] == name) local_files.splice (n,1);

    if (local_files.length > 49) local_files.splice (0,3);
    local_files.push ({'name': name, 'data': data});
  }
  else
  {
    for (var n = local_files.length - 1; n >= 0; n--)
      if (local_files [n]['name'] == name)
        return (local_files [n]['data']);
  }
  return "";
}

////////////////////////////////
///// function: local_link /////
////////////////////////////////

function local_link (url, local)
{
  if (url [0] == "+")
  {
    var dat = fs.existsSync (aliases) ? fs.readFileSync (aliases, "utf8") : "";
    var n = dat.indexOf (url + ","); if (n < 0) n = dat.indexOf (url + "?,");
    if (n < 0) url = ""; else
    {
      url = dat.substr (n + url.length + 1, 300);
      url = url.substr (url.indexOf ("+") + 1);
      url = url.substr (0, url.indexOf (";"));
      if (url && local > 0) console.log (" FILE: " + url);
    }
  }
  return (url.toLowerCase() == aliases ? "" : url);
}

//////////////////////////////
///// function: put_file /////
//////////////////////////////

function put_file (request, response, url, local)
{
  var append = url.substr (0,2) == "++"; if (append) url = url.substr (1);

  if (url [0] != "+" || !(url = local_link (url + "?", local)))
  {
    if (append || fs.existsSync (url)) { default_handler (response, 777, local); return; }
  }

  append = (append && fs.existsSync (url)) ? fs.statSync (url).size : 0;

  var stream = fs.createWriteStream (url, append ? { start: append, flags: "a" } : {});

  stream.on ("error", function (err) { default_handler (response, 777, local); });

  stream.on ("open", function()
  {
    proc_done (response, "", "", local);
    request.pipe (stream, { end:true });
  });
}

//////////////////////////////
///// function: get_file /////
//////////////////////////////

function get_file (request, response, url, local)
{
  var data = local_data (url, ""), size = 0;

  if (!data) url = local_link (url, local); else
  {
    proc_done (response, data, mime_type (url), 0); return;
  }

  if (fs.existsSync (url)) size = fs.statSync (url).size;
  if (!size) { default_handler (response, 777, local); return; }
  var start = 0, end = size - 1, range = request.headers ["range"];

  if (!range) size = -size; else
  {
    range = range.substr (range.indexOf ("=") + 1);
    range = range.split ("-"); end = range[1] ? range[1] * 1 : 0;
    if (range[0]) start = range[0] * 1; else { start = size - end - 1; end = 0; }
    if (!end || end >= size) end = size - 1;
    if (start > end) start = end;
    if (end < start) end = start;
  }

  var stream = fs.createReadStream (url, { start: start, end: end });

  stream.on ("error", function (err) { default_handler (response, 777, local); });

  stream.on ("open", function()
  {
    proc_done (response, [size, start, end], mime_type (url), local);
    stream.pipe (response, { end:true });
  });
}

//////////////////////////////////
///// function: http_handler /////
//////////////////////////////////

function http_handler (request, response)
{
  var n, local = portnum = 0;
  var proxy, origin = host = cookie = refer = "";
  var referral = head = head1 = head2 = head3 = m3ufix1 = m3ufix2 = "";
  var method = request.method, url = request.url.replace (/\\/g, "/");

  if (url.substr (0,1) != "/") url = ""; else
  {
    local = 1; url = url.substr (1);
  }

  if (url.substr (0,1) == "?")
  {
    proxy_command (response, url.substr (1)); return;
  }

  if (url.substr (0,1) == "~")
  {
    local = -1; url = url.substr (1); referral = "~";
  }

  if (!url || url [0] == ".")  // filter out ".well-known"
  {
    default_handler (response, 0, 0); return;
  }
  
  url = url.replace (/%7C/g, "|");  // Opera and Chrome convert vertical bar to %7C
  // note: (^) is replaced with %5E and anything after (#) is stripped (all browsers)

  if (method == "OPTIONS" && options_proc (request, response, local)) return;

  if (local >= 0) console.log ((local ? ">" : "?") + method + " " + url);

  if (url.search (":|/") < 0)
  {
    if (url [0] == "!") url = url.substr (1);
    n = url.indexOf ("?"); if (n >= 0) url = url.substr (0, n);
    if (!local || url.length < 3) default_handler (response, 888, local);
    else if (method == "GET") get_file (request, response, url, local);
    else if (method == "PUT") put_file (request, response, url, local);
    else if (method == "POST") handle_special (request, response, url, local);
    else default_handler (response, 888, local);
    return;
  }

  if (url.substr (0,1) == "*")
  {
    url = url.substr (1); n = url.indexOf ("*");
    if (n >= 0) { refer = url.substr (0, n); url = url.substr (n + 1); }
    referral = referral + "*" + refer + "*"; if (!refer) refer = "*";
  }

  if ((n = url.indexOf ("|*")) >= 0)
  {
    head = url.substr (0, n).split ("|"); url = url.substr (n + 2);
  }

  if ((n = refer.indexOf (",")) >= 0)
  {
    m3ufix1 = refer.substr (n + 1); if (!(refer = refer.substr (0, n))) refer = "*";

    if ((n = m3ufix1.indexOf (",")) >= 0)
    {
      if (n >= 0) { m3ufix2 = m3ufix1.substr (n + 1); m3ufix1 = m3ufix1.substr (0, n); }
      
      if ((n = url.indexOf (".m3u")) > 0)
      {
        var m = url.indexOf ("?"); if (m < 0) m = url.length;
        if (m > n + 3 && m < n + 7) local += local;
      }
    }
  }

  if (url.substr (0,1) == "!")  // for DASH videos
  {
    n = url.indexOf ("/"); var ext = url.substr (n + 1);
    url = local_data (url.substr (1, n - 1), "") + ext;
  }

  n = url.indexOf (":");
  if (n < 0 || n > 5) { url = refer + url; n = url.indexOf (":"); }
  if (n > 0 && n < 6) { origin = url.substr (0, n + 3); host = url.substr (n + 3); }

  url = "/"; n = host.indexOf ("/");
  if (n > 0) { url = host.substr (n); host = host.substr (0, n); }

  if ((n = host.indexOf ("?")) > 0)
  {
    url = "/" + host.substr (n) + url; host = host.substr (0, n);
  }

  if ((n = host.indexOf (":")) >= 0)
  {
    portnum = host.substr (n + 1) * 1; host = host.substr (0, n);
  }

  if (origin == "http://") { proxy = http; if (!portnum) portnum = 80; }
  if (origin == "https://") { proxy = https; if (!portnum) portnum = 443; }

  if (!host || !proxy)
  {
    default_handler (response, 999, local); return;
  }

  var myheader = request.headers, cookie = myheader ["accept"];
  myheader ["host"] = host; origin = origin + host;

  if (!cookie || cookie.substr (0,2) != "**") cookie = ""; else
  {
    myheader ["accept"] = "*/*";
    cookie = cookie.substr (2); if (!cookie) cookie = "null";
    if (cookie != "null") myheader ["cookie"] = cookie;
  }

  if (refer == "null") refer = myheader ["referer"]; else
  {
    if (refer == "*") refer = origin + "/";
    if (refer) myheader ["origin"] = myheader ["referer"] = refer; else
      { delete myheader ["origin"]; delete myheader ["referer"]; }
  }
  if (!refer) refer = "null";

  if (head) for (var i = head.length - 1, j, f, g, h; i >= 0; i--)
  {
    f = head[i]; j = f.indexOf ("=");
    if (!head1) head1 = "*"; head1 = f + "|" + head1;

    if (f && j) if (j < 0) head2 = f + (head2 ? ", " : "") + head2; else
    {
      g = f.substr (0, j); h = f.substr (j + 1);
      if (g [0] == "!") head3 = head3 + "|" + g.substr(1) + "|" + h; else
      {
        myheader [g] = decodeURIComponent (h); if (!h) delete myheader [g];
      }
    }
  }

  //  deprecated because does not work with some servers
  //  if (local < -1 || local > 1) myheader ["accept-encoding"] = "identity";   // no compression

  if (!m3ufix1 && m3ufix2) url = url.replace ("\.ts", "." + m3ufix2);  // for misleading mpeg-2 extension

  if (local > 0) n = ++reqcount; else n = 0;

  var config = {
    method: method, host: origin, refer: refer, referral: referral, cookie: cookie,
    count: n, fix1: m3ufix1, fix2: m3ufix2, headers: head1, exposes: head2, mimics: head3
  }

  dns_lookup (dns_resolve (host), function (addr) { http_process (addr ? addr : host); });

  function http_process (addr)
  {  
    var options = {
      method: method, hostname: addr, port: portnum, path: url,
      headers: myheader, requestCert: false, rejectUnauthorized: false,
      ciphers: 'HIGH'  // note at end of file
    }

    if (addr == "0.0.0.0") { default_handler (response, 999, local); return; }

    proxy = proxy.request (options, function (res) { proc_handler (response, res, config, local); });

    proxy.on ("error", function () { default_handler (response, 666, local); });

    request.on  ("close", function () { proxy.destroy(); });
    response.on ("close", function () { proxy.destroy(); });

    request.pipe (proxy, { end:true });
  }
}

//////////////////////////////////
///// function: proc_handler /////
//////////////////////////////////

function proc_handler (response, res, config, local)
{
  var n, s, v, buffer = "", custom_header = false, header = {};

  var status = res.statusCode; var message = res.statusMessage;

  if (local > 0)
  {
    last_time = 0; n = config.count;
    console.log (" Request " + n + " - Status " + status + " (" + message + ")");
  }
  else if (local < 0)
  {
    var the_time = Date.now() / 1000; passthru++;
    var delay = last_pass == config.host ? 30 : 20;

    if (last_time <= the_time - delay)
    {
      last_time = the_time; last_pass = config.host;
      console.log ("<Passthrough " + passthru + " - " + last_pass + " - " + config.refer);
    }
  }

  if (local <= 0 || config.method == "OPTIONS") header = res.headers; else
  {
    var header_name = [
      "connection", "content-type", "content-length", "content-encoding",
      "content-range", "accept-ranges"
    ];

    v = config.exposes.replace (/\s/g, "");
    if (v) header_name = header_name.concat (v.split (","));

    for (n = 0; n < header_name.length; n++)
    {
      s = header_name [n]; v = res.headers [s]; if (v) header [s] = v;
    }

    if (config.cookie && (v = res.headers ["set-cookie"]))
    {
      s = "zz-set-cookie"; header [s] = v; custom_header = true;
    }
  }

  if ((v = res.headers [(s = "location")]))
  {
    var x = config.host, y = v.substr (0,2);
    if (y [0] == "/") { if (y == "//") x = x.substr (0, x.indexOf (y)); v = x + v; }
    if (config.cookie) { delete (header [s]); s = "zz-location"; custom_header = true; }
    header [s] = (custom_header ? v : proxy_host + config.referral + config.headers + v);
  }

  s = "access-control-expose-headers"; v = res.headers [s]; if (!v) v = "";
  if (custom_header) v = v + (v ? ", " : "") + "zz-location, zz-set-cookie";
  if (config.exposes) v = v + (v ? ", " : "") + config.exposes;
  if (v) header [s] = v;

  if (v = header [(s = "set-cookie")])
  {
    for (n = 0; n < v.length; n++) header [s][n] = v[n].substr (0, v[n].indexOf (";"));
  }

  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";

  if (config.mimics)
  {
    var i, j, k = config.mimics.split ("|");
    for (n = 1; n < k.length; n += 2)
    {
      i = k [n]; j = k [n + 1]; if (!i) continue;
      if (j) header [i] = j; else delete header [i];
    }
  }

  if (config.method == "OPTIONS")
  {
    s = "access-control-allow-headers"; v = res.headers [s];
    header [s] = (v = v ? v + ", " : "") + "Accept";
    header ["access-control-max-age"] = "86400";
  }

  if (local > -2 && local < 2)
  {
    response.writeHead (status, message, header);
    res.pipe (response, { end:true });
    return;
  }

  var proc = null; v = header ["content-encoding"];
  if (v == "gzip") proc = zlib.createGunzip();
  if (proc) res.pipe (proc); else proc = res;

  proc.on ("error", function () { default_handler (response, 777, local); });

  proc.on ("data", function (data)
  {
    if (buffer.length < 250000) buffer = buffer + data.toString();
  });

  proc.on ("end", function ()
  {
    if (local == -2 || local == 2)
    {
      var mydata = tweak_m3u8 (buffer, config);
      header ["content-encoding"] = "identity";
      header ["content-length"] = mydata.length;
      response.writeHead (status, message, header);
      response.end (mydata);
    }
  });
}

///////////////////////////////////
///// function: https_handler /////
///////////////////////////////////

function https_handler (request, response)
{
  default_handler (response, 0, 0);
}

///////////////////////////////////
///// function: proxy_command /////
///////////////////////////////////

function proxy_command (response, cmd)
{
  var n, p, q, msg, str = setdns = ""; cmd = decodeURIComponent (cmd);

  if ((n = cmd.indexOf ("=")) > 0) { str = cmd.substr (n + 1); cmd = cmd.substr (0, n); }

  cmd = cmd.trim(); str = str.trim(); msg = "Command: " + cmd + (str ? " " + str : "");

  if (!proxy_tunnel) { cmd = ""; str = "Tunnel Proxy (port " + socks_port + ") is offline"; }

  if (cmd == "flags")
  {
    cmd = ""; if (isNaN (n = str * 1)) n = 0; if (str) proxy_flags = n & 31;
    str = "Console output is " + (proxy_flags & 1 ? "enabled" : "disabled");
    str += "\n\nExpecting TOR at port " + (proxy_flags & 2 ? tor2_port : tor1_port);
    if (proxy_flags & 4) str += "\n\n> TOR is enabled for ALL <";
  }

  if (cmd == "reload")
  {
    if (!str) str = settings; str = init_settings (str) + " (" + str + ")";
    cmd = ""; console.log (">> " + str); str += "\n"; //setdns = "default";
  }

  if (cmd == "activate")
  {
    cmd = ""; if (!str) add_resolver (""); p = str.split (",");
    for (n = 0; n < p.length; n++) if (q = p[n].trim()) add_resolver (q);

    p = init_servers().split(" "); q = '-'.repeat (31);
    q = "\n" + q + "\nsee console for progress report\n" + q + "";
    str = " Resolved = " + p[0] + "\n\n  Pending = " + p[1] + "\n" + q;
  }

  if (cmd == "servers")
  {
    setdns = str; str = cmd = "";
    for (n = 0; n < server.length; n += 2)
    {
      if (!(p = server [n + 1])) p = "NO ADDRESS";
      if (p == "TOR") p += " Network"; if (p == "LOCAL") p += " Domain";
      str += " " + p + ' '.repeat (17 - p.length) + "> " + server[n] + "\n";
    }
  }

  if (cmd == "dnslookup" && (n = str.indexOf ("=")) >= 0)
  {
    setdns = str.substr (0, n); str = str.substr (n + 1);
  }

  p = dns_servers (setdns); q = doh_address ? " DOH  " + doh_address + "\n" : "";
  if (!p.length) q = " DNS lookup in progress!\n   Please try again...\n";
  for (n = 0; n < p.length; n++) q += " DNS" + (n+1) + " " + p[n] + "\n";

  p = "_".repeat ((n = msg.length) < 25 ? 25 : n);
  msg += "\n" + p + "\n\n" + q + p + "\n\n";

  if (cmd == "dnslookup" && str)
  {
    if ((n = str.indexOf ("//")) >= 0) str = str.substr (n + 2);
    if ((n = str.indexOf ("/")) >= 0) str = str.substr (0, n);
    if ((n = str.indexOf (":")) >= 0) str = str.substr (0, n);

    var func; p = str.replace (/\d|\./g, ""); msg += str + "\n\n";
    if (p) func = dns.resolve4; else if (net.isIP (str)) func = dns.reverse;

    if (func) func (str, function (err, addr)
    {
      if (err) str = "Not resolved\n"; else
        for (n = 0, str = ""; n < addr.length; n++) str += " " + addr [n] + "\n";

      proc_done (response, msg + str, "text/plain", 0);
    });
    if (func) return;
  }

  if (cmd) str = "What??\n"; proc_done (response, msg + str, "text/plain", 0);
}

///////////////////////////////////
///// function: proxy_handler /////
///////////////////////////////////

function proxy_handler (sock)
{
  var n, host, port, addr, conn, tor = false, socket = ++sockets_count; ++sockets_open;

  sock.on ("error", function () { });
  sock.on ("close", function () { socks_report (0, 1, --sockets_open); socks_abort(); });
  sock.on ("end",   function () { });  // this callback is needed for the "close" event

  sock.once ("data", function (d) { socks_phase_1 (d); });

  function socks_abort ()
  {
    // if socket is still open then drain the pipe before destroying
    if (sock.readyState == "open") sock.end (function () { socks_close(); }); else socks_close();
  }

  function socks_close ()
  {
    if (conn) conn.destroy(); sock.destroy();
  }

  function socks_phase_1 (d)
  {
    if (d.length != 3 || d[0] != 5 || d[1] != 1 || d[2] != 0) socks_abort(); else
    {
      sock.write (Buffer.from ("\5\0"));
      sock.once ("data", function (d) { socks_phase_2 (d); });
    }
  }

  function socks_phase_2 (d)
  {
    n = 8; if (d.length < 10 || (d[3] == 3 && (n = d[4] + 5) > d.length - 2)) n = 0;
    if (n == 8) if (d[3] != 1) n = 0; else host = d[4] + "." + d[5] + "." + d[6] + "." + d[7];

    if (!n) socks_abort(); else
    {
      if (n > 8) host = d.toString ('utf8', 5, n); port = d.readUInt16BE (n);
      addr = proxy_flags & 4 ? "TOR" : tor_resolve (host); socks_report (0, 0, 0);
      dns_lookup (addr, function (ip) { addr = ip ? ip : host; socks_phase_3 (d); });
    }
  }

  function socks_phase_3 (d)
  {
    if (addr == "0.0.0.0") { socks_abort(); return; }

    if (addr != "TOR") conn = net.createConnection (port, addr); else
    {
      tor = true; n = proxy_flags & 2 ? tor2_port : tor1_port;
      conn = net.createConnection (n, "localhost");
    }

    conn.on ("connect", function () { socks_phase_4 (d); });
    conn.on ("error",   function(e) { socks_report (e.code, e.address, addr); });
    conn.on ("close",   function () { socks_report (0, 2, sock.readyState); socks_abort(); });
    conn.on ("end",     function () { });  // this callback is needed for the "close" event
  }

  function socks_phase_4 (d)
  {
    if (!tor) { socks_phase_5 (null); return; } conn.write (Buffer.from ("\5\1\0"));

    conn.once ("data", function (r)
    {
      if (r.length != 2 || r[0] != 5 || r[1] != 0) socks_abort(); else
      {
        conn.write (d); conn.once ("data", function (d) { socks_phase_5 (d); });
      }
    });
  }

  function socks_phase_5 (d)
  {
    if (d && (d[0] != 5 || d[1] != 0 || d[2] != 0)) socks_abort(); else
    {
      sock.write (Buffer.from ("\5\0\0\1\0\0\0\0\0\0"));
      conn.pipe (sock, { end:true }); sock.pipe (conn, { end:true });
    }
  }

  function socks_report (err, data1, data2)
  {
    var msg = ">> " + (proxy_flags & 16 ? socket + " - " : "");

    if (err)
    {
      if (tor) console.log ("TOR fail"); else if (proxy_flags & 1)
        console.log (msg + "ERR: " + err + " - " + (data1 ? data1 : data2) + " - " + host);
      return;
    }

    if (!(proxy_flags & 1)) return;
    if (data1 == 0) console.log (msg + host + " <" + port + "> " + (addr != host ? addr : ""));

    if (!(proxy_flags & 16)) return;
    if (data1 == 1) console.log (" @ " + socket + " - " + data2 + (conn ? "" : " (cancelled)"));
    if (data1 == 2) console.log (" : " + socket + " - " + data2);
  }
}

////////////////////////////////
///// function: tweak_m3u8 /////
////////////////////////////////

function tweak_m3u8 (data, config)
{
  var regx, fix1 = config.fix1, fix2 = config.fix2;

  if (data.substr (0,5).indexOf ("#") < 0) return (data);

  if (!fix1 && fix2)
  {
    regx = RegExp ("\." + fix2 + "\n", 'g');
    data = data.replace (regx, ".ts" + "\n");
  }

  if (!fix1) fix1 = fix2 = "/"; if (!fix2) fix2 = fix1;
  var myfix = proxy_host + config.referral + config.headers;

  if (fix1.substr (0,4) != "http")
  {
    regx = RegExp ("\nhttp", 'g');
    data = data.replace (regx, "\n" + myfix + "http");
    regx = RegExp ('URI="http', 'g');
    data = data.replace (regx, 'URI="' + myfix + "http");
  }

  if (fix1.substr (0,1) == "/") myfix = myfix + config.host;

  regx = RegExp ("\n" + fix1, 'g');
  data = data.replace (regx, "\n" + myfix + fix2);
  regx = RegExp ('URI="' + fix1, 'g');
  data = data.replace (regx, 'URI="' + myfix + fix2);

  return (data);
}

////////////////////////////////////
///// function: handle_special /////
////////////////////////////////////

function handle_special (request, response, url, local)
{
  var mode = 0, buffer = "";

  if (url == "wanna_boot_dash") mode = 1;
  if (url == "wanna_boot_dash_live") mode = 2;

  if (url.substr (0, 14) == "wanna_scratch=") mode = 3;

  if (!mode) { default_handler (response, 888, local); return; }

  request.on ("data", function (data)
  {
    if (buffer.length < 10000) buffer = buffer + data.toString();
  });

  request.on ("end", function ()
  {
    if (mode == 3)
    {
      local_data (url.substr (14), buffer);
      proc_done (response, "", "", 0); return;
    }

    var name = mode == 1 ? "_blank_dash_mpd.txt" : "_blank_live_mpd.txt";
    var data = fs.existsSync (name) ? fs.readFileSync (name, "utf8") : "";

    if (!data) default_handler (response, 777, local); else
    {
      handle_boot_dash (data, buffer, url); proc_done (response, "", "", 0);
    }
  });
}

//////////////////////////////////////
///// function: handle_boot_dash /////
//////////////////////////////////////

function handle_boot_dash (data, buffer, url)
{
  var sub = buffer.split ("|"); if (sub.length < 9) return;
  var dat = sub[5].split (","); if (dat.length < 4) return;

  var target = data.toString(); var name = "_" + url + "_" + sub[6];

  target = target.replace ("~run_time~"  , sub[0]);
  target = target.replace ("~aud_mime~"  , sub[1]);
  target = target.replace ("~aud_codec~" , sub[2]);
  target = target.replace ("~vid_mime~"  , sub[3]);
  target = target.replace ("~vid_codec~" , sub[4]);

  target = target.replace ("~aud_init~"  , dat[0]);
  target = target.replace ("~aud_index~" , dat[1]);
  target = target.replace ("~vid_init~"  , dat[2]);
  target = target.replace ("~vid_index~" , dat[3]);

  target = target.replace (/~seg_num~/g  , dat[0]);
  target = target.replace (/~seg_ofs~/g  , dat[1]);
  target = target.replace (/~seg_dur~/g  , dat[2]);

  var aud_url = name + "-aud";
  var vid_url = name + "-vid";

  target = target.replace ("~aud_url~", proxy_host + "~!" + aud_url);
  target = target.replace ("~vid_url~", proxy_host + "~!" + vid_url);

  local_data (name, target);
  local_data (aud_url, sub[7]);
  local_data (vid_url, sub[8]);
}

///// End of file /////

/*
Below is the cipher list when using "ciphers: 'HIGH'".
With Wireshark, I took a pcap of the node.js TLS handshake.
The TLS fingerprint matches Cluster #33 (https://tlsfingerprint.io/cluster/a0c7d616ebdc8b4c).
Normally, node.js matches https://tlsfingerprint.io/id/6dc4898ff8f86cfb which does not compare with any browser.
Still cannot get past CloudFlare's "Bot Fight Mode" which is currently active at banned.video (September 22, 2020).
Why in the hell is CloudFlare blocking Kraker?


TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)
TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)
TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)


TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009f)
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xccaa)
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x009e)
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0xc024)
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xc028)
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x006b)
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xc023)
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xc027)
TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x0067)
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)
TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)
TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)
TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003d)
TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003c)
TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff
*/
