// News & Propaganda

document.getElementById ("src6").innerHTML = `
  <option value= "youtube" class="w">YouTube MP4 / WEBM
  <option value= "fox"        >+ m3u - Fox
  <option value= "abc"        >+ mp4 - ABC
  <option value= "cbs"        >? m3u - CBS
  <option value= "cnbc"       >+ m3u - CNBC
  <option value= "cnn"        >? m3u - CNN
  <option value= "cspan"      >? m3u - C-SPAN
  <option value= "msnbc"      >+ m3u - MS/NBC
  <option value= "pbs"        >+ m3u - PBS
  <option value= "cbc"        class="w">+ m3u - CBC
  <option value= "cpac"       class="w"># m3u - CPAC
  <option value= "ctv"        class="w">+ mpd - CTV
  <option value= "global"     class="w">+ mp4 - Global
  <option value= "tvo"        class="w">+ mp4 - TVO
  <option value= "bbc"        class="b">+ m3u - BBC
  <option value= "presstv"    class="b">? m3u - Press TV
  <option value= "aljazeera"  class="b">+ mp4 - Al Jazeera
  <option value= "bloomberg"  class="b">+ m3u - Bloomberg
  <option value= "deutsche"   class="b">? m3u - Deutsche Welle
  <option value= "epochtimes" class="b">? m3u - Epoch Times
  <option value= "brightcove" class="r">+ mp4 - BrightCove
`;

document.getElementById ("butt6").innerHTML = `
  <button onclick="copylist(this,6,1)">Fox</button>
  <button onclick="copylist(this,6,2)">PBS</button>
  <button onclick="copylist(this,6,3)">BBC</button>
`;

table_6 = [
  "",
  "Fox             m3u8/mp4  +   No Proxy     https://www.foxnews.com  https://www.foxbusiness.com",
  "ABC             mp4       +   Proxy        https://abcnews.go.com",
  "CBS             m3u8      ?   Proxy        https://www.cbsnews.com",
  "CNBC            m3u8      +   Proxy        https://www.cnbc.com",
  "CNN             m3u8      ?   No Proxy     https://www.cnn.com  https://edition.cnn.com",
  "C-SPAN          m3u8      ?   Proxy        https://www.c-span.org",
  "MS/NBC          m3u8      +   Proxy        https://www.msnbc.com  https://www.nbcnews.com",
  "PBS             m3u8      +   Proxy        https://www.pbs.org",
  "CBC             m3u8      ?   Proxy        https://www.cbc.ca",
  "CPAC            m3u8      #   No Proxy     https://www.cpac.ca",
  "CTV             mpd       +   Proxy (DIG)  https://www.ctvnews.ca  https://www.ctv.ca",
  "Global          mp4       +   Proxy        https://globalnews.ca",
  "TVO             mp4       +   Proxy (DIG)  https://www.tvo.org",
  "BBC             m3u8      +   Proxy        https://www.bbc.com  https://www.bbc.co.uk/sounds",
  "Press TV        m3u8      ?   Proxy        https://www.presstv.ir",
  "Al Jazeera      mp4       +   Proxy (DIG)  https://www.aljazeera.com",
  "Bloomberg       m3u8      +   Proxy        https://www.bloomberg.com",
  "Deutsche Welle  mp4       #   No Proxy     https://www.dw.com",
  "Epoch Times     m3u8      ?   Proxy        https://www.theepochtimes.com  http://www.ntd.com",
];

frame_6 = {
  1: 'fox', 2: 'pbs', 3: 'bbc', req_youtube: request,
  req_brightcove: load_brightcove, dig_brightcove: find_brightcove
};

stack_6_1 = copylist (`
`);

stack_6_2 = copylist (`
  Austin City Limits: 40 Years (2014)	2:2365338020
  Frontline: WikiSecrets (2011)		2:1946795242
`);

stack_6_3 = copylist (`
  Dragonfly				3:p035dt58
  Desert Art				3:p076m7sh
  Follow the Food			3:p07bj7pv
`);

frame_6.req_fox = async (id, frame, fmt) =>
{
  var tag = "fox"; id = getid (frame, id, 13);
  if (!id || is_busy (frame, tag + " (ID)", 0)) return;
  var url, src = "https://api.foxnews.com/v3/video-player/" + id;

try
{
  response = await kitty (cors_local + src);
  jsonData = await response.json();

  if (jsonData.error != undefined)
  {
    src = "https://api.foxbusiness.com/v3/video-player/" + id;
    response = await kitty (cors_local + src);
    jsonData = await response.json();
    if (jsonData.error != undefined) throw ("!!!");
  }

  url = jsonData.channel.item["media-group"]["media-content"][0]["@attributes"].url;

  if (!url) throw ("!!!"); else if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

  var n = url.indexOf ("?");
  if (n > 0 && url.includes ("/tokenvod.")) url = url.substr (0, n);

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_6.req_abc = async (id, frame, fmt) =>
{
  var tag = "abc"; id = getid (frame, id, -10);
  if (!id || is_busy (frame, tag + " (ID)", 0)) return;
  var url = "https://abcnews.go.com/video/itemfeed?id=" + id;

try
{ 
  response = await kitty (cors_bypass + url);
  jsonData = await response.json();

  url = jsonData.channel.item["media-group"]["media-content"][1]["@attributes"].url;
  if (!url.includes (".m3u8")) throw ("!!!");

  if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id);
}
////////////////////

frame_6.req_cnbc = async (id, frame, fmt) =>
{
  var tag = "cnbc"; id = getid (frame, id, 10);
  if (!id || is_busy (frame, tag + " (ID)", 0)) return;
  var url = "https://player.cnbc.com/p/gZWlPC/cnbc_global?playertype=synd&byGuid=" + id;

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  if (!(url = pullstring (textData, '"playbackURL":"', '"'))) throw ("!!!");
  if (url.substr (0,2) == "//") url = "https:" + url;

  if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_6.req_msnbc = async (id, frame, fmt) =>
{
  var tag = "msnbc"; id = getid (frame, id, -13);
  if (!id || is_busy (frame, tag + " (ID)", 0)) return;
  var n, url = "https://www.msnbc.com/msnbc/embedded-video/mmvo" + id;

//var url = "https://www.nbcnews.com/news/embedded-video/mmvo" + id;

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  n = textData.lastIndexOf ('"videoAssets":['); url = textData.substr (n);
  url = pullstring (url, '"publicUrl":"', '"'); if (!url) throw ("!!!");

  response = await kitty (url, { method: 'HEAD' });
  url = response.url; if (!url.includes (".m3u8")) throw ("!!!");

  if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_6.req_pbs = async (id, frame, fmt) =>
{
  var tag = "pbs"; id = getid (frame, id, 10);
  if (!id || is_busy (frame, tag + " (ID)", 0)) return;
  var url = "https://player.pbs.org/portalplayer/" + id + "/";

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  url = pullstring (textData, '"encodings": ["', '"'); if (!url) throw ("!!!");

  response = await kitty (cors_bypass + url + "?format=jsonp&callback=__jp1");
  textData = await response.text();

  url = pullstring (textData, '"url": "', '"'); if (!url) throw ("!!!");

  if (!url.includes ("m3u8") || stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_6.req_cbc = async (id, frame, fmt) =>
{
  var tag = "cbc"; id = getid (frame, id, -10);
  if (!id || is_busy (frame, tag + " (ID)", 0)) return;

  var s = '{"query":"{contentItem(sourceId:\\"' + id + '\\"){media{id assets{key}}}}"}';
  var t = { 'content-type': 'application/json' }
  var url = "https://www.cbc.ca/graphql";

try
{
  response = await kitty (cors_local + url, { method: 'POST', body: s, headers: t });
  textData = await response.text();

  url = pullstring (textData, '"key":"', '"'); if (!url) throw ("!!!");

  response = await kitty (cors_local + url);
  jsonData = await response.json();

  if (!(url = jsonData.url)) throw ("!!!");

  if (url.includes (".m3u8")) if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }
  else if (url.includes (".mp3")) fmt = "audio"; else throw ("!!!");

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_6.req_cpac = async (id, frame, fmt) =>
{
  var tag = "cpac"; id = getid (frame, id, 36);
  if (!id || is_busy (frame, tag + " (ID)", 0)) return;
  var url = "https://www.cpac.ca/api/1/services/contentModel.json?url=%2Fsite%2Fwebsite%2Fepisode%2Findex.xml&crafterSite=cpacca&id=" + id;

try
{ 
  response = await kitty (cors_local + url);
  jsonData = await response.json();

  if (!(url = jsonData.page.details.videoUrl)) throw ("!!!");

  if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_6.req_ctv = async (id, frame, fmt) =>
{
  var tag = "ctv"; id = getid (frame, id, 7);
  if (!id || is_busy (frame, tag + " (ID)", 0)) return;

  var hub = ["ctvnews_web", "ctv_hub", "ctvthrowback_hub"];
  var url = "https://capi.9c9media.com/destinations/xxx/platforms/desktop/contents/" + id;
  var n, s, sub = "?%24include=%5BContentPackages%5D";

try
{
  for (n = 0; n < hub.length; n++)
  {
    s = url.replace ("xxx", hub [n]);
    response = await kitty (cors_bypass + s + sub);
    jsonData = await response.json(); if (response.status == 200) break;
  }

  url = s + "/contentpackages/" + jsonData.ContentPackages[0].Id + "/manifest.mpd";
  if (cors_local) url += "##" + cors_local + "~https://license.9c9media.ca/widevine";
  stream_all (frame, 2);

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id);
}
////////////////////

frame_6.req_global = async (id, frame, fmt) =>
{
  var tag = "global"; id = getid (frame, id, -8);
  if (!id || is_busy (frame, tag + " (ID)", 0)) return;
  var url = "https://globalnews.ca/video/embed/" + id;

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  url = pullstring (textData, 'sources":[{"file":"', '"');
  url = url.replace (/\\/g, "");

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id);
}
////////////////////

frame_6.req_tvo = async (id, frame, fmt) =>
{
  load_brightcove (id, frame, fmt, "18140038001", "tvo");
}
////////////////////

frame_6.req_bbc = async (id, frame, fmt) =>
{
  var tag = "bbc"; id = getid (frame, id, 8);
  if (!id || is_busy (frame, tag + " (ID)", 0)) return;
  var url = "https://open.live.bbc.co.uk/mediaselector/6/select/version/2.0/mediaset/pc/vpid/" + id + "/format/xml/atk/";

//var url = "https://open.live.bbc.co.uk/mediaselector/6/select/version/2.0/mediaset/pc/vpid/" + id + "/format/json/cors/1";

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  var s, sub = textData.split ("<connection"); url = "";

  for (s of sub)
  {
    if (!s.includes ("https:") || !s.includes (".m3u8")) continue;
    url = pullstring (s, 'href="', '"'); if (url) break;
  }

  if (!url) throw ("!!!"); else if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_6.req_aljazeera = async (id, frame, fmt) =>
{
  var tag = "aljazeera", pub = "665003303001", x = id.split ("-");
  if (x.length > 1) { id = x [1]; if (pub != x [0]) { pub = x [0]; tag = ""; }}
  load_brightcove (id, frame, fmt, pub, tag);
}
////////////////////

frame_6.req_bloomberg = async (id, frame, fmt) =>
{
  var tag = "bloom"; id = getid (frame, id, 36, 22);
  if (!id || is_busy (frame, tag + " (ID)", 0)) return;
  var url = "https://www.bloomberg.com/multimedia/api/embed?id=" + id;
  var f = [0,0,0,0], u = [], n;

try
{
  response = await kitty (cors_bypass + url);
  jsonData = await response.json();

  url = jsonData.streams[0].url; if (!url) throw ("!!!");

  if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_6.dig_fox = async (url, frame, fmt) =>
{
  var tag = "fox"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  var s = 'data-video-id="', n = textData.indexOf (s);
  if (n < 0) { s = "video_id="; n = textData.indexOf (s); }

  if (n > 0) url = textData.substr (n + s.length, 13); else
  {
    s = 'data-url="'; n = textData.indexOf (s);
    if (n > 0)
    {
      url = textData.substr (n + s.length, 200);
      url = url.substr (url.indexOf ("/v/") + 3, 13);
    }
    else
    {
      s = "redirect.mp3"; n = textData.indexOf (s); if (n < 0) throw ("!!!");
      url = textData.substr (n + s.length + 2, 200);
      url = url.substr (0, url.indexOf ('"')); if (url == "") throw ("!!!");
      url = "https://" + url.replace (/\\/g, "");
      busy = -busy;
    }
  }
  busy = -busy;

} catch (err) { console.log (err); busy = 0; }

  if (busy > 0)
  {
    no_fail (frame); loadwindow (url, frame, tag, "?");
  }
  else if (no_fail (frame)) frame_6.req_fox (url, frame, fmt);
}
////////////////////

frame_6.dig_abc = async (url, frame, fmt) =>
{
  var tag = "abc"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  url = pullstring (textData, 'data-video="', '"');
//  if (!url) url = pullstring (textData, '"videoId":"', '"');
  if (!url) url = pullstring (textData, '/video/itemfeed?id=', '"');
  if (!url) url = pullstring (textData, 'playlist":[{"id":"', '"');

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) frame_6.req_abc (url, frame, fmt);
}
////////////////////

frame_6.dig_cbs = async (url, frame, fmt) =>
{
  var n, s, tag = "cbs"; if (is_busy (frame, tag + " (DIG)", 0)) return;

//https://cbsi.live.ott.irdeto.com/widevine/getlicense

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  if (s = pullstring (textData, '"embedUrl":"', '"'))
    if ((s = url.replace (/\\/g, "")) != url)
    {
      if (s.includes ("/live/")) throw ("!!!");
      response = await kitty (cors_bypass + s);
      textData = await response.text();
    }

  n = textData.indexOf ("defaultPayload");
  if (n > 0) textData = textData.substr (n);

  url = pullstring (textData, '"video":"', '"');

  if (!url.includes (".m3u8"))
  {
    url = pullstring (textData, '"streamingUrl":"', '"');
    stream_all (frame, 2); url = url.replace (/\\/g, "");
    if (!url.includes (".mpd")) throw ("!!!");
  }
  else if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame)) loadwindow (url, frame, tag, "?", fmt);
}
////////////////////

frame_6.dig_cnbc = async (url, frame, fmt) =>
{
  var tag = "cnbc"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  url = pullstring (textData, "'content_id' : '", "'");
  if (!url) url = pullstring (textData, 'data-vilynx-id="', '"');

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) frame_6.req_cnbc (url, frame, fmt);
}
////////////////////

frame_6.dig_cnn = async (url, frame, fmt) =>
{
  var s, t, tag = "cnn"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{ 
  response = await kitty (cors_local + url);
  textData = await response.text();

  t = pullstring (textData, '"TOP_AUTH_SERVICE_APP_ID":"', '"');
  s = pullstring (textData, 'data-video-id="', '"'); if (!s || !t) throw ("!!!");

  url = "https://medium.ngtv.io/v2/media/" + s + "/desktop?appId=" + t;

  response = await kitty (cors_local + url);
  textData = await response.text();

  url = pullstring (textData, '"url":"', '"'); if (!url) throw("!!!");

  if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame)) loadwindow (url, frame, tag, "?", fmt);
}
////////////////////

frame_6.dig_cspan = async (url, frame, fmt) =>
{
  var tag = "cspan"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  if (url = pullstring (textData, 'data-altbcid="', '"'))
  {
    busy = -busy; url += "~*,,*?hdnts=" + pullstring (textData, 'data-akamaitoken="', '"');
  }
  else
  {
    if (!(url = pullstring (textData, "[{file: '", "'"))) throw ("!!!");

    if (stream_all (frame, 1)) fmt = 0; else
    {
      response = await kitty (url); textData = await response.text();
      [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
    }
  }

} catch (err) { console.log (err); busy = 0; }

  if (busy < 0)
  {
    no_fail (frame); load_brightcove (url, frame, -fmt, "3617315736001", "cspan"); return;
  }

  if (no_fail (frame)) loadwindow (url, frame, tag, "?");
}
////////////////////

frame_6.dig_msnbc = async (url, frame, fmt) =>
{
  var n, s, tag = "msnbc"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  if (!(url = pullstring (textData, 'video":{"id":"mmvo', '"')))
  {
    s = pullstring (textData, '"embedURL":"', '"');
    if (!s) s = pullstring (textData, '"embedUrl":"', '"');
    url = pullstring (s, "/mmvo", "");
  }

  if (url)
  {
    if (url.length < 11 || url.length > 13) throw ("!!!");
    busy = 0; frame_6.req_msnbc (url, frame, fmt); return;
  }

  s = pullstring (s, "/config/", '?'); if (!s) throw ("!!!");
  url = pullstring (textData, '"MPX":{', '}'); if (!url) throw ("!!!");

  var a = pullstring (url, '"pid":"', '"');
  var b = pullstring (url, '"playerName":"', '"');

  url = "https://player.theplatform.com/p/" + a + "/" + b + "/" + s;

  response = await kitty (cors_bypass + url);
  textData = await response.text();

  url = pullstring (textData, ':releaseUrl="', '?'); if (!url) throw ("!!!");
  url += "?switch=HLSServiceSecure&formats=M3U,MPEG4";

  if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame)) loadwindow (url, frame, tag, "?", fmt);
}
////////////////////

frame_6.dig_pbs = async (url, frame, fmt) =>
{
  var tag = "pbs"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  if (url = pullstring (textData, '<iframe src="https://player', '"'))
  {
    url = pullstring (url, "player/", ""); if (!url) throw ("!!!");
    var s = pullstring (url, "", "/"); if (s) url = s;
  }
  else
  {
    url = pullstring (textData, "'VideoTPMediaId': '", "'");
    if (!url) url = pullstring (textData, '"videoTPMediaId\\":', ',');
    if (!url) url = pullstring (textData, 'data-coveid="', '"');
    if (!url) url = pullstring (textData, 'data-coveId="', '"');
    if (!url) url = pullstring (textData, '"tp_media_id":"', '"');
    if (!url) throw ("!!!");
  }

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) frame_6.req_pbs (url, frame, fmt);
}
////////////////////

frame_6.dig_cbc = async (url, frame, fmt) =>
{
  var tag = "cbc"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  url = pullstring (textData, "'clipId': '", "'");
  if (!url) url = pullstring (textData, '"clipID":"', '"');
  if (!url) url = pullstring (textData, '"identifier":"', '"');
  if (!url) throw ("!!!");

} catch (err) { console.log (err); busy = 0; }

  if (busy < 0)
  {
    no_fail (frame); loadwindow (url, frame, tag, "?", fmt); return;
  }

  busy = -busy; if (no_fail (frame)) frame_6.req_cbc (url, frame, fmt);
}
////////////////////

frame_6.dig_ctv = async (url, frame, fmt) =>
{
  var tag = "ctv"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  url = pullstring (textData, '&contentId=', '"');
  if (!url) url = pullstring (textData, "axisId&#34;:&#34", "&");
  if (!url) throw ("!!!");

/*
  if (!url) url = pullstring (textData, "); initPlayer(", ")");
  if (!url) url = pullstring (textData, 'data-video-id="', '"');
  if (!url) url = pullstring (textData, "contentId: ", ",");
  if (!url) url = pullstring (textData, "currentId=", "&");

  if (!url && (url = pullstring (textData, 'getAuthStates("', '"')))
    if (!(url = url.split (",")).length) url = ""; else url = url [url.length - 1];

  if (!url && (url = pullstring (textData, '"axisId":', 'title')))
  {
    if (!cors_kraker) throw ("???");
    var s = pullstring (url, '"heroBrand":"', '"'), t = pullstring (url, "", ",");
    s = s.replace (/hub\b/, "_hub");

    url = "https://capi.9c9media.com/destinations/" + s + "/platforms/desktop/contents/" + t;

    response = await kitty (cors_local + url + "?%24include=%5BContentPackages%5D");
    jsonData = await response.json();

    url += "/contentpackages/" + jsonData.ContentPackages[0].Id + "/manifest.mpd";
    url += "##" + cors_kraker + "~https://license.9c9media.ca/widevine";

    stream_all (frame, 2); no_fail (frame); loadwindow (url, frame, tag, "?"); return;
  }
*/

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) frame_6.req_ctv (url, frame, fmt);
}
////////////////////

frame_6.dig_global = async (url, frame, fmt) =>
{
  var tag = "global"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{
/*
  if (doc.includes ("watch.globaltv.com"))
  {
    s = pullstring (doc, "/movie/", "");
    if (!s) s = pullstring (doc, "/video/", "");
    if (!s) s = pullstring (doc, "/episode/", "");

    n = s.indexOf ("?"); if (n > 0) s = s.substr (0, n); if (!s) throw ("!!!");
    n = s.indexOf ("/"); if (n > 0) s = s.substr (0, n);

    t = { path: '/authorization/authorizeresource', data: { duid: '1f152a54-ac6c-43ae-8a01-e2f0a86acfa7' }};
    t.data.resource_id = s; s = JSON.stringify (t);

    t = { 'content-type': 'application/json' };
    u = cors_bypass + "https://global.corusappservices.com/";

    url = u + "authorization/untrusted/sign";
    response = await kitty (url, { method: 'POST', headers: t, body: s });
    textData = await response.text();

    s = pullstring (textData, '"data":', '}') + "}";

    url = u + "authorization/authorizeresource";
    response = await kitty (url, { method: 'POST', headers: t, body: s });
    textData = await response.text();

    s = pullstring (textData, 'data":"', '"').split(".")[1];
    s = pullstring (atob (s), '"data":', '}') + ',"platform":"web_widevine"}';

    url = u + "media/getstream";
    response = await kitty (url, { method: 'POST', headers: t, body: s });
    textData = await response.text();

    s = pullstring (textData, 'data":"', '"').split(".")[1];
    url = pullstring (atob (s), '"streaming_url":"', '"'); if (!url) throw ("!!!");

    stream_all (frame, 2); no_fail (frame); loadwindow (url, frame, tag, "?"); return;
  }
*/

  response = await kitty (cors_bypass + url);
  textData = await response.text();

  var s = pullstring (textData, 'data-displayinline="', '"');
  if (!s) s = pullstring (textData, 'data-miniplayer-video="', '"');
  if (!s) s = pullstring (textData, '<iframe src="', '"');
  if (!s) throw ("!!!");

  url = pullstring (s, "/playlist/", "/");
  if (!url) url = pullstring (s, "/embed/", "/"); if (!url) throw ("!!!");

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) frame_6.req_global (url, frame, fmt);
}
////////////////////

frame_6.dig_tvo = async (url, frame, fmt) =>
{
  var tag = "tvo"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{
  var s = "/" + url.split ("/").slice (3).join ("/");
  url = "https://hmy0rc1bo2.execute-api.ca-central-1.amazonaws.com/graphql";

  s = '{"operationName":"getVideo","variables":{"slug":"' + s + '"},"query":"query getVideo($slug:String)' +
      '{getTVOOrgVideo(slug:$slug) { assetUrl videoSource { brightcoveRefId }}}"}';

  response = await kitty (cors_local + url, { method: 'POST', body: s, });
  textData = await response.text();

  url = pullstring (textData, 'brightcoveRefId":"', '"'); if (!url) throw ("!!!");

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) frame_6.req_tvo (url, frame, fmt);
}
////////////////////

frame_6.dig_bbc = async (url, frame, fmt) =>
{
  var tag = "bbc"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  url = pullstring (textData, 'embed\\/', '\\');
//  if (!url) url = pullstring (textData, '[{"id":"', '"');
//  if (!url) url = pullstring (textData, '[{\\"id\\":\\"', '\\"');
  if (!url) url = pullstring (textData, 'versionID&quot;:&quot;', '&');
  if (!url) url = pullstring (textData, 'data-vpid="', '"');
  if (!url) url = pullstring (textData, 'data-id="', '"');
  if (!url) url = pullstring (textData, '"vpid":"', '"');
  if (!url) url = pullstring (textData, '/vpid/', '.');
  if (!url) url = pullstring (textData, '"versionId":"', '"');

  if (!url) if (!(url = pullstring (textData, '"videoPid":"', '"'))) throw ("!!!"); else
  {
    var n = textData.indexOf ('"pid":"' + url + '"'); if (n < 0) throw ("!!!");
    n = textData.indexOf ('"versionPid":"', n); if (n < 0) throw ("!!!");
    url = textData.substr (n + 14, 20); url = url.substr (0, url.indexOf ('"'));
  }

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) frame_6.req_bbc (url, frame, fmt);
}
////////////////////

frame_6.dig_deutsche = async (url, frame, fmt) =>
{
  var tag = "deutsche"; if (is_busy (frame, tag + " (ID)", 0)) return;

try
{
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  url = pullstring (textData, '<source src="', '"'); if (!url) throw ("!!!");

  if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_6.dig_presstv = async (url, frame, fmt) =>
{
  var tag = "presstv"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  if (!(url = pullstring (textData, 'file: "', '"'))) throw ("!!!");

  if (!url.includes (".m3u8") || stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame)) loadwindow (url, frame, tag, "?", fmt);
}
////////////////////

frame_6.dig_aljazeera = async (url, frame, fmt) =>
{
  var tag = "aljazeera"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  url = pullstring (textData, "RenderPagesVideo('", "'");
  if (!url) url = pullstring (textData, "RenderGeneralBCVideo(", ",");
  if (!url) url = pullstring (textData, 'data-video-id="', '"');
  if (!url || url.replace (/\d/g, "")) url = pullstring (textData, '"video":"', '"');

  if (!url)
  {
    url = pullstring (textData, '"embedUrl":"', '"');
    if (!url) url = pullstring (textData, '"embedUrl": "', '"');
    url = pullstring (url, "?videoId=", ""); if (!url) throw ("!!!");
  }

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) frame_6.req_aljazeera (url, frame, fmt);
}
////////////////////

frame_6.dig_bloomberg = async (url, frame, fmt) =>
{
  var tag = "bloom"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  if (url = pullstring (textData, 'data-url="', '"'))
  {
    response = await kitty (cors_bypass + url);
    textData = await response.text();
  }

  url = pullstring (textData, '"resourceId":"', '"'); if (!url) throw ("!!!");

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) frame_6.req_bloomberg (url, frame, fmt);
}
////////////////////

frame_6.dig_epochtimes = async (url, frame, fmt) =>
{
  var tag = "epochtimes"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  url = pullstring (textData, '"contentUrl":"', '"'); if (!url) throw ("!!!");

  if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame)) loadwindow (url, frame, tag, "?", fmt);
}
////////////////////


