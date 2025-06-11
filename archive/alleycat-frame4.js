// Notes and links

document.getElementById ("blob1").innerHTML = `<p><hr><p>No release notes at this time.`;

document.getElementById ("blob2").innerHTML = `

<p><hr><p>

<h3 id="notes">Special Notes</h3>
<ul><li>
Vimeo live streaming (m3u8) is supported. Requires Kraker or a CORS unblocker.
</li><li>
Odysee live streaming is supported. Requires Kraker.
</li><li>
InfoWars and Twitter videos play as m3u8 but the mp4 version is available via the DLoad button.
</li><li>
Twitter Spaces and Broadcasts are supported (example ID: 1OwxWwDyXnQxQ).
</li><li>
For Twitter short links (like "https://t.co/..."), use DIG to get the tweet ID.
</li><li>
Only podcasts are supported on iHeartRadio.
</li><li>
A Rumble page link (example: "https://rumble.com/v1wac7i-world-premier-died-suddenly.html") will work as an
embed ID if you remove the hyphenated part. However, using the page link in this manner can sometimes
retrieve the wrong video.
</li></ul><p>

Sites accessible with a Podcast DIG:<br>
&nbsp;- https://podcasts.apple.com<br>
&nbsp;- https://itunes.apple.com<br>
&nbsp;- https://www.stitcher.com<br>
&nbsp;- https://radiopublic.com<br>
&nbsp;- https://overcast.fm<br>
&nbsp;- https://www.podbean.com<br>
&nbsp;- https://www.spreaker.com
<p>
Sites accessible with a Brightcove DIG:<br>
&nbsp;- https://www.stuff.co.nz<br>
&nbsp;- https://www.nzherald.co.nz<br>
&nbsp;- https://www.thesun.co.uk<br>
&nbsp;- https://www.the-sun.com<br>
&nbsp;- https://www.channel4.com/news<br>
&nbsp;- https://www.express.co.uk<br>
&nbsp;- https://www.miamiherald.com<br>
&nbsp;- https://time.com<br>
&nbsp;- http://webtv.un.org<br>
&nbsp;- https://www.military.com<br>
&nbsp;- https://peopletv.com<br>
&nbsp;- https://www.skynews.com.au<br>
&nbsp;- https://www.news.com.au<br>
&nbsp;- https://nypost.com

<p><hr><p>

<h3 id="sites" class="skinny"><r_>Sites List</r_>
  <small> -- Go to <a href="#info">Info viewer</a> or <a href="#news">News viewer</a>
    or <a href="#free">Movie viewer</a></small></h3>

<table class="links" style="padding:2px 0"></table><p>

? = works with DIG only<br>
# = works with Play ID only<br>
+ = works with both DIG and Play ID<br>
$ = use the Sandbox option to embed the original video
<p>
KRAK = accessible with the Kraker Local Proxy Server only<br>
KRKR = accessible with the Kraker Remote Proxy (may have limitations)<br>
CORS = accessible with a CORS unblocker (or Kraker Local)

<p><hr><p>

<h3 id="movies" class="skinny"><r_>Movie Sites</r_>
  <small> -- Go to <a href="#info">Info viewer</a> or <a href="#news">News viewer</a>
    or <a href="#free">Movie viewer</a></small></h3>

<table class="links" style="padding:2px 0"></table><p>

! on a site url = use caution on the site due to popup ads<br>
@ instead of # indicates site accepts IMDB and TMDB IDs
<p>
Some search sites to get video links from:
<p>
<a target=_blank href="https://www.downloads-anymovies.com">www.downloads-anymovies.com</a><br>
<a target=_blank href="https://flicktv.net">flicktv.net</a> &nbsp;
<a target=_blank href="https://tubemotion.net">tubemotion.net</a><br>
<a target=_blank href="https://www.levidia.ch">www.levidia.ch</a><br>
<a target=_blank href="https://www.primewire.tf">www.primewire.tf</a><br>
<p>
Find tmdb IDs:
<a target=_blank href="https://www.themoviedb.org">www.themoviedb.org</a>&nbsp;
<a target=_blank href="https://catflix.su">catflix.su</a>
<p>
Find imdb IDs: <a target=_blank href="https://www.imdb.com">www.imdb.com</a><br>

<p><hr><p>

`;

var getid = function (frame, str)
{
  var m, n, s, t, len, arg = 2; if (!str) str = "";

  if (str [0] == "*") if (str = str.substr (1)) return (str);
  t = (str.replace (/[/=]/g, "\n")).split("\n").pop().split(".");
  str = t.pop(); if (t.length && str.length < 5) str = t.pop();

  if (str) while (arg < arguments.length) if (len = arguments [arg++])
  {
    s = str.substr (-(m = len < 0 ? -len : len));
    if (len < 0) s = s.substr (s.lastIndexOf ("-") + 1);
    n = s.length; if (n == m || (len < 0 && n > m - 3)) return (s);
  }
  else return (str);

  if (!busy && frame) no_fail (frame, "", "Invalid ID: " + str); return ("");
}
////////////////////

var crack_source = function (data, frame, fmt)
{
  var sub, str, url, i, j, f = [0,0,0,0], r = [0,0,0,0];

  sub = data.split ("<source src="); if (sub.length < 2) return "";

  for (i = 1; i < sub.length; i++)
  {
    str = sub [i]; j = str.indexOf ('label='); str = str.substr (j + 6);
    j = str.indexOf (str[0], 1) - 1; str = str.substr (1, j); j = str.length - 1;
    if (str[j] == "p") str = str.substr (0, j); if (str == "original") str = "720";
    if ((j = chkformat (str)) >= 0) if (r[j] < str) { f[j] = i; r[j] = str; }
  }

  fmt = getformat (f, fmt); fixformat (f, frame);
  if ((j = argformat (fmt)) < 0) return "";

  str = sub [f[j]]; fmt = r[j]; j = str.indexOf (str[0], 1) - 1;
  url = str.substr (1, j); if (url == "") return "";

  return (url + "<>" + fmt);
}
////////////////////

var crack_smil = function (data, frame, fmt)
{
  var sub, url, i, j, k, w, h, b, m3u = "", levels = [];

  if (s = pullstring (data, '<audio src="', '"')) return (s + "<>");

  sub = data.split ('<video src="'); if (sub.length < 2) return "";

  for (i = 1; i < sub.length; i++) if (url = sub [i])
  {
    if (!(k = pullstring (url, '', '"'))) continue;
    if (k.includes (".m3u8")) { m3u = i; continue; }
    w = pullstring (url, 'width="', '"');
    h = pullstring (url, 'height="', '"');
    b = pullstring (url, 'bitrate="');
    levels.push ({ width: w, height: h, bitrate: b, url: k });
  }

  k = formats_list (levels); fmt = getformat (k, fmt); url = m3u;
  if (j >= 0) { url = levels [j].url; fixformat (k, frame); }
  return (url + "<>" + fmt);
}
////////////////////

var find_brightcove = async (url, frame, fmt, xtag) =>
{
  var tag = xtag, pub, id; if (!tag) tag = "brightcove";
  if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  if (url = pullstring (textData, 'vms-embedcode="', '"'))  // for www.news.com.au
  {
    pub = pullstring (url, "", "-"); id = pullstring (url, "-", "");
    if (!pub || !id) pub = id = "";
  }

  if (!pub) pub = pullstring (textData, 'data-account="', '"');
  if (!pub) pub = pullstring (textData, 'accountId":"', '"');  // for www.skynews.com.au
  if (!pub) pub = pullstring (textData, 'data-deferred-account="', '"');  // for nypost.com
  if (!pub) throw ("!!!");

  if (!id) id = pullstring (textData, 'data-video-id="', '"');
  if (!id) id = pullstring (textData, 'data-video-id-pending="', '"');
  if (!id) id = pullstring (textData, 'data-brightcove-video-id="', '"');
  if (!id) id = pullstring (textData, 'assetId":"', '"');  // for www.skynews.com.au
  if (!id) id = pullstring (textData, 'data-deferred-video-id="', '"');  // for nypost.com
  if (!id) throw ("!!!");

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) load_brightcove (id, frame, fmt, pub, xtag);
}
////////////////////

var load_brightcove = async (id, frame, xfmt, pub, xtag) =>
{
  var i, j, k, fmt, tag, krak = "", key = "", f = [0,0,0,0], r = [0,0,0,0];
  if ((fmt = xfmt) < 0) fmt = -fmt; if (!(tag = xtag)) tag = "brightcove";
  if (is_busy (frame, tag + " (ID)", 0)) return;

  if ((i = id.indexOf ("?")) >= 0)
  {
    key = id.substr (i); id = id.substr (0, i);
  }

  if ((i = id.indexOf ("~")) >= 0)
  {
    krak = id.substr (i); id = id.substr (0, i);
  }

  if (!pub)
  {
    i = id.indexOf ("-"); pub = id.substr (0, i); id = id.substr (i + 1);
  }
  
try
{
  var url = "https://players.brightcove.net/" + pub + "/default_default/index.min.js";
  if (pub.length < 9 || pub.length > 13 || id.length < 10 || id.length > 13) throw ("!!!");

  response = await kitty (cors_bypass + url);
  textData = await response.text();

  var s = 'accountId:"' + pub + '",policyKey:"';
  var n = textData.indexOf (s); if (n < 0) throw ("!!!");

  var pk = textData.substr (n + s.length, 200);
  pk = pk.substr (0, pk.indexOf ('"'));

  url = "https://edge.api.brightcove.com/playback/v1/accounts/" + pub + "/videos/" + id;

  response = await kitty (cors_bypass + url, { headers: { accept: 'application/json;pk=' + pk }, });
  textData = await response.json();

  var url_m3u8 = ""; var dat = textData.sources; if (dat == undefined) throw ("!!!");

  for (i = 0; i < dat.length; i++)
  {
    url = dat [i].src; if (url == undefined) continue;
    if (url.indexOf ("m3u8") > 0) { url_m3u8 = url; continue; }
    k = dat [i].height; if (k == undefined) continue;

    if ((j = chkformat (k)) >= 0) if (r[j] < k) { f[j] = i + 1; r[j] = k; }
  }

  if ((k = getformat (f, fmt)))
  {
    if ((k = argformat (k)) < 0 || (k = f[k] - 1) < 0) throw ("!!!");
    url = dat [k].src; fmt = dat [k].height; fixformat (f, frame);
  }
  else
  {
    if (!(url = url_m3u8)) throw ("!!!"); url = krak + url + key;

    if (stream_all (frame, 1)) fmt = 0; else
    {
      response = await kitty (url); textData = await response.text();
      [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
    }
  }

} catch (err) { console.log (err); busy = 0; }

  if (!xtag) id = pub + "-" + id; if (xfmt < 0) id = "id-none";
  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

var request = async (id, frame, fmt) =>
{
  if (id [0] == "@") try
  {
    if (is_busy (frame, "youtube")) return;
    id = "https://www.youtube.com/embed/live_stream?channel=" + id.substr (1);
    response = await kitty (cors_bypass + id); textData = await response.text();
    id = pullstring (textData, '<link rel="canonical" href="', '"');
    busy = -busy; no_fail (frame);
  }
  catch (err) { console.log (err); busy = 0; no_fail (frame); return; }

  var s = id.split ("?"), t = pullstring ("&" + s[1] + "&", "&v=", "&");
  id = t || s[0]; id = getid (frame, id, 11); if (!id) return;

  if (stream_all (frame, 0)) if (is_busy (frame, "youtube")) return; else
  {
    var url = "https://www.youtube.com/embed/" + id;
    no_fail (frame); loadwindow (url, frame, "youtube", id); return;
  }

  var src = document.getElementById ("ytx" + frame).value;

  if (src == 1) if (fmt < 0) src = 0; else { request_youtube (id, frame, fmt); return; }
  if (src == 9) if (fmt < 0) src = 0; else { request_youtube (id, frame, -fmt); return; }

  if (!src && cors_kraker) { request_youtube (id, frame, fmt); return; }

  invidious_link = invidious_site [src]; request_invidious (id, frame, (fmt < 0 ? -fmt : fmt));
}
////////////////////

const request_invidious = async (id, frame, fmt) =>
{
  var i, j, n, f = [0,0,0,0,0,0,0,0];

  var tag = "invidious"; if (is_busy (frame, tag + " (ID)")) return;
  var url = invidious_link + "/api/v1/videos/" + id + "?fields=formatStreams,hlsUrl";

try
{
  response = await kitty (cors_local + url);
  jsonData = await response.json();

  var sub = jsonData.formatStreams; if (!sub) throw ("!!!"); n = sub.length;

  for (i = 0; i < n; i++)
  {
    if ((j = argformat (sub[i].itag)) >= 0) f[j] = i + 1;
  }
    
  if ((n = getformat (f, fmt)))
  {
    fmt = n; fixformat (f, frame); n = f[argformat(n)] - 1;
    url = (sub[n].url.indexOf ("&gcr=") > 0) ? "local=true&" : "";  // geo-restricted?
    url = invidious_link + "/latest_version?" + url + "itag=" + fmt + "&id=" + id;
  }
  else   // live stream
  {
    url = jsonData.hlsUrl; if (!url) throw ("!!!");
    if (url.substr (0,1) == "/") url = invidious_link + url;
    sub = url = url + "?local=true";

    if (stream_all (frame, 1)) fmt = ""; else
    {
      response = await kitty (url); textData = await response.text();
      [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
    }
  }

} catch (err) { console.log (err); busy = 0; }

  fmt = argformat (fmt); fmt = pixformat (fmt);
  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

/*
Youtube DRM formats:
142 143 144 145 146 148 149 150 161
222 223 224 225 226 227 273 274 275 279 280
317 318 350 351 352 357 358 359 360 

https://www.youtube.com/iframe_api

t.context = { client: { gl: 'US', hl: 'en', clientName: 'WEB', clientVersion: '2.20230426.02.00' }};
t.context = { client: { gl: 'US', hl: 'en', clientName: 'ANDROID_EMBEDDED_PLAYER', clientVersion: '16.02' }};
t.context = { client: { gl: 'US', hl: 'en', clientName: 'WEB_EMBEDDED_PLAYER', clientVersion: '1.20241009.01.00' }};
t.context = { client: { gl: 'US', hl: 'en', clientName: 'TVHTML5_SIMPLY_EMBEDDED_PLAYER', clientVersion: '2.0' }};
t.playbackContext = { contentPlaybackContext: { signatureTimestamp: "sts", html5Preference: "HTML5_PREF_WANTS" }};
t.context.thirdParty = { embedUrl: 'https://www.youtube.com' };
*/

// https://www.youtube.com/watch?v=VaSV4NtZCXU - mp4 video with webm audio
// yt-dlp --proxy http://127.0.0.1:8084 --no-check-certificates --simulate https://www.youtube.com/embed/74VHwppfHuI
// https://raw.githubusercontent.com/bashonly/yt-dlp/refs/heads/master/yt_dlp/extractor/youtube/_video.py

const request_youtube = async (id, frame, fmt) =>
{
  var tag = "youtube"; if (is_busy (frame, tag + " (ID)", 2)) return;
  var i, j, n, r, s, t, u, url, sub, vid, aud, key, nkey, base, dash;
  var f = [0,0,0,0,0,0,0,0,0,0], ua = cors_kraker + "user-agent=|*";

try
{
  response = await kitty (ua + "https://www.youtube.com/embed/" + id);
  textData = await response.text();

  s = pullstring (textData, '"visitorData":"', '"');
  ua = ua.replace ("|*", "|x-goog-visitor-id=" + s + "|*");

  base = pullstring (textData, '"jsUrl":"', '"'); if (!base) throw ("!!!");
  key = cookies [base]; nkey = cookies ["!" + base]; n = cookies ["?" + base];

  if (!key || !nkey || !n)
  {
    response = await kitty (ua + "https://www.youtube.com" + base);
    textData = await response.text();
/*
    i = textData.indexOf ("timedtext_video"); j = textData.lastIndexOf ("split", i);
    r = textData.substring (j, i); s = pullstring (r, "(", "["); if (!s) throw ("aaa");

    s = "var " + s + '='; i = textData.indexOf (s); t = textData [i + s.length];
    j = textData.indexOf (t == "[" ? '"],' : '"),', i); if (i < 0 || j < 0) throw ("bbb");
    u = ";\n" + textData.substring (i, j + 2) + ";\nvar nsig=";

    i = textData.indexOf ('.slice(0,0))'); if (i < 0) throw ("ccc");
    i = textData.lastIndexOf ("func", i); j = textData.indexOf ('.join(', i);
    t = textData.substring (i, j); s = "var " + pullstring (t, "typeof ", "==");
    nkey = s + pullstring (textData, s, ";") + u + t + ".join('')}; sig=nsig(sig);";

    r = pullstring (r, ";", "return"); s = "var " + pullstring (r, "", ".") + "={";
    t = pullstring (textData, s, "};"); u = pullstring (r, "(", ","); if (!t) throw ("ddd");
    key = ""; //s + t + "}; var " + u + "=sig.split('');\n" + r + "sig=" + u + ".join('');";
*/

    i = textData.indexOf (s = "'use strict'") + 1; j = textData.indexOf ("=", i) + 1;
    if (!i || !j) throw ("aaa"); j = textData.indexOf (textData [j] == "[" ? '"],' : '"),', j);
    u = textData.substring (i + s.length, j + 2) + ";\n";

    s = pullstring (textData, "FORMAT_STREAM_TYPE_UNKNOWN", "(decode");
    s = pullstring (s, '"alr"', ''); s = pullstring (s, "=", ""); if (!s) throw ("bbb");
    s = "var xx=" + pullstring (textData, ";\n" + s + "=", "}") + "};\n";

    t = "var " + pullstring (s, ";", "[") + "="; t += pullstring (textData, t, "};");
    cookies [base] = key = s + t + "};\n" + u + "sig=xx(sig);";

    i = textData.indexOf ("privateDoNotAccess"); if (i < 0) throw ("ccc");
    i = textData.indexOf ("{var ", i); i = textData.lastIndexOf ("func", i);
    j = textData.indexOf ("this.", i); j = textData.lastIndexOf ("};", j);
    t = "var xx=" + textData.substring (i, j + 2);

    s = "var " + pullstring (t, "typeof ", "=="); s += pullstring (textData, s, ";");
    cookies ["!" + base] = nkey = s + ";\n" + u + t + "\nsig=xx(sig);";

    n = pullstring (textData, "signatureTimestamp:", "}") * 1;
    if (n) cookies ["?" + base] = n; else n = Math.trunc (Date.now() / 86400000) - 1;
  }

  t = {
    videoId: id, playbackContext: { contentPlaybackContext: { signatureTimestamp: n }},
    context: { client: { gl: 'US', hl: 'en', clientName: 'WEB_EMBEDDED_PLAYER', clientVersion: '1.20241009.01.00' }}
  }
  url = ua + "https://www.youtube.com/youtubei/v1/player"; s = { 'content-type': 'application/json' }

  response = await kitty (url, { method: 'POST', headers: s, body: JSON.stringify (t) });
  jsonData = await response.json();

  if (!(sub = jsonData.streamingData))
  {
    t.context.client.clientName = 'TVHTML5'; t.context.client.clientVersion = '7.20241201.18.00';

    response = await kitty (url, { method: 'POST', headers: s, body: JSON.stringify (t) });
    jsonData = await response.json(); if (!(sub = jsonData.streamingData)) throw ("!!!");
  }

  if (fmt < 0 && (fmt = -fmt) && (t = sub.adaptiveFormats))
  {
    for (i = 0; i < t.length; i++)
      if ((s = t[i].itag) && (j = isdashfmt (s)) >= 0)
        if (t[i].approxDurationMs || t[i].targetDurationSec) f[j] = i + 1;

    if (!f[8]) f[0] = f[1] = f[2] = 0;
    if (!f[9]) f[4] = f[5] = f[6] = 0;
    if (getformat (f, fmt)) dash = true;
  }

  if (!dash && (t = sub.formats)) for (i = 0; i < t.length; i++)
    if ((s = t[i].itag) && (j = argformat (s)) >= 0) f[j] = i + 1;

  fmt = getformat (f, fmt); fixformat (f, frame); i = argformat (fmt);
  if (i < 0 || (j = f[i] - 1) < 0) throw ("!!!"); fmt = pixformat (i);

  vid = yt_split (t [j]); url = yt_sign (vid [0], vid [1], key, nkey);

  if (!url) throw ("!!!"); else if (dash)
  {
    var webm = i > 3; aud = yt_split (t [f [webm + 8] - 1]);
    var v = aud [3] + "," + vid [3], w = "wanna_boot_dash";

    sub = yt_sign (aud [0], aud [1], key, nkey); if (!sub) throw ("!!!");

    download = "YouTube DASH download links (" + id + ") -- " +
      "<a href='" + sub + "'>Audio</a> &nbsp;" +
      "<a href='" + url + "'>Video</a>";

    if (!(s = vid [2]))  // livestream
    {
      v = "x-head-seqnum"; w = "x-head-time-sec"; s = "~" + v + "|" + w + "|*";

      response = await kitty (cors_kraker + s + url, { method: 'HEAD' });

      v = response.headers.get (v); if (!v) throw ("!!!");
      w = response.headers.get (w); if (!w) throw ("!!!");

      var seg_num = v * 1; var seg_ofs = w * 1;
      var seg_dur = Math.round (10 * seg_ofs / seg_num) / 10;
      n = Math.ceil (90 / seg_dur); // initial 90-second progress bar; can be up to 3 hours

      seg_num -= n; seg_ofs -= Math.round (n * 10 * seg_dur) / 10;
      if (seg_num < 1 || seg_ofs < 1) seg_num = seg_ofs = 0;

      v = seg_num + "," + seg_ofs + "," + seg_dur + ",";
      w = "wanna_boot_dash_live"; s = "";
    }
    else
    {
      response = await kitty (cors_kraker + "~" + url, { method: 'HEAD' });
      if (response.status != 200) throw ("???");
    }

    aud = aud [4] || (webm ? "opus" : "mp4a.40.2");
    vid = vid [4] || (webm ? "vp9" : "avc1.4d401e");

    t = (webm ? "w" : "m") + fmt + "(" + id + ").mpd";
    s += "|" + (webm ? "audio/webm" : "audio/mp4") + "|" + aud;
    s += "|" + (webm ? "video/webm" : "video/mp4") + "|" + vid;
    s += "|" + v + "|" + t + "|" + sub + "|" + url + "|";

    await kitty (cors_kraker + w, { method: 'POST', body: s } );
    url = cors_kraker + "_" + w + "_" + t; tag = "yt-dash"; stream_all (frame, 2);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

const yt_split = function (data)
{
  var d, i, j, m, s = "", u = data.url;

  if (!u) if (!(u = data.signatureCipher)) u = ""; else
  {
    u = u.replace (/%25/g, "%"); u = decodeURIComponent (u);
    s = pullstring (u, "s=", "&"); u = pullstring (u, "url=", "");
  }

  i = (d = data.initRange)  ? d.start + "-" + d.end : "";
  j = (d = data.indexRange) ? d.start + "-" + d.end : "";
  d = data.approxDurationMs || 0; m = data.mimeType || "";

  return ([u, s, d / 1000, i + "," + j, pullstring (m, '"', '"')]);
}
////////////////////

var yt_sign = function (url, sig, key, nkey)
{
  if (url && sig && key) { eval (key); url += "&sig=" + sig; }
  sig = pullstring (url, "&n=", "&"); if (!nkey || !sig) return url;
  key = "&n=" + sig; eval (nkey); return (url.replace (key, "&n=" + sig));
}
////////////////////

///// Support for Kraker AES encrypt/decrypt /////

var b64_bin = function (x)
{
  var m = [], n = 0; try { x = atob (x); } catch { x = "" };
  for (; n < x.length; n++) m.push (x.charCodeAt (n)); return (m);
}

var bin_b64 = function (x)
{
  var n, p = "", q = "", s = typeof (x) == "string"; if (s) x = str2bin (x);
  for (n of x) p += String.fromCharCode (n); p = btoa (p); if (s) return (p);
  for (n = 0; n < p.length; n += 64) q += p.substr (n, 64) + "\n"; return (q);
}

var bin2hex = function (x)
{
  var n, p = "", q = "", s = typeof (x) == "string"; if (s) x = str2bin (x);
  for (n of x) p += ("0" + (n.toString (16))).substr (-2); if (s) return (p);
  for (n = 0; n < p.length; n += 64) q += p.substr (n, 64) + "\n"; return (q);
}

var hex2bin = function (x)
{
  var m = [], n = 0; x = x.replace (/\s/g, ""); 
  if (x.replace (/[a-f0-9A-F]/g, "") || x.length & 1) x = "";
  for (; n < x.length; n += 2) m.push (parseInt (x.substr (n,2), 16)); return (m);
}

var bin2str = function (x)
{
  if (Array.isArray (x)) x = new Uint8Array (x);
  return (typeof (x) == "string" ? x : new TextDecoder().decode (x));
}

var str2bin = function (x)
{
  return (Array.from (new TextEncoder().encode (x)));
}

var pussyfoot = async (action, chunk) =>
{
  action = "/~gotta_pussyfoot=" + action; if (!chunk) chunk = "";

  try {
    if (Array.isArray (chunk)) chunk = new Uint8Array (chunk);
    var resp = await fetch (action, { method: 'POST', body: chunk });
    var data = await resp.arrayBuffer(); if (resp.status != 200) data = "";
  }
  catch { data = "" }

  data = new Uint8Array (data); return (data.length ? data : "");
}
