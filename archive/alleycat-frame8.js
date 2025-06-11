// Internet Radio

radio = copylist (`Talk Radio | Cool Music | Funky Music | Just Garbage | More Garbage

Fox News Talk			https://live.amperwave.net/manifest/foxnewsradio-foxnewsradioaac-imc
++				https://radio.foxnews.com/
Talk Radio UK			http://radio.talkradio.co.uk/stream
++				https://ukradiolive.com/talkradio/schedule
WABC Talk Radio			http://playerservices.streamtheworld.com/api/livestream-redirect/WABCAM.mp3
++				https://wabcradio.com/show-schedule/
Republic Broadcasting		https://cast2.my-control-panel.com/proxy/rbn/stream
++				http://republicbroadcasting.org/program-schedule/
American Family Radio		https://mediaserver3.afa.net:8443/talk.mp3
++				https://afr.net/podcasts/afr-program-lineup/
Blaze Radio			http://19303.live.streamtheworld.com/BLZE_1AAC.aac
++				https://www.theblaze.com/st/radio
Red State Talk			http://s2.radio.co/s572ad25f7/listen
++				https://redstatetalkradio.com/schedule/
The Fringe FM			https://ais-edge101-live365-dal02.cdnstream.com/a05030
++				https://fringe.fm/
Voice America			http://ice8.securenetsystems.net/VARIETY
++				https://www.voiceamerica.com/Schedule/schedule
BBS Talk Radio 1		http://cast.bbstalkradio.com/proxy/bbsradio?mp=/stream
++				https://bbsradio.com/station1and2schedule
BBS Talk Radio 2		http://cast.bbstalkradio.com/proxy/bbsradio2?mp=/stream
++				https://bbsradio.com/station1and2schedule
Revolution Radio Studio A	http://s1.voscast.com:8054/;
++				https://revolution.radio/Schedules-A&B.html
Revolution Radio Studio B	http://s2.voscast.com:8186/;
++				https://revolution.radio/Schedules-A&B.html
Rense Radio Live		https://s9.voscast.com:9311/live
++				https://www.renseradio.com
Alex Jones Live			http://stream-mp3.infowars.com/
++				https://www.infowars.com/radio-archive
--
--
--
--
<b_>CFRA</b_>			http://18063.live.streamtheworld.com:80/CFRAAMAAC_SC
				
Star FM Rock Classics		http://stream.starfm.de/classic/mp3-192/radiode
Rockin Doc Radio		http://radio.rockindocradio.net:8600/;
Lynx Classic Rock		http://rock-lynxradio.radioca.st/;
Antenna Web			http://mars.streamerr.co:8066/stream/1/
Radio Caroline			http://sc2.radiocaroline.net:10568/;
Bar Legend Radio		http://solid24.streamupsolutions.com:8010/stream/1/
Dance Wave			http://stream.dancewave.online:8080/dance.mp3
Salsa Mexico			http://colombiawebs.com.co:8106/;
Disco Classics Radio		https://discoclassicradio.nl/stream
Lounge Radio			http://nl1.lounge-radio.com:8010/;
Absolute Trance Radio		http://strm112.1.fm/trance_mobile_mp3
Starlite Radio			http://centova.radioservers.biz:8021/;
--
--
--
--
--
--
--
--

Virtual DJ: ClubZone		http://virtualdjradio.com:8000/channel1.mp3
Virtual DJ: TheGrind		http://virtualdjradio.com:8000/channel2.mp3
Virtual DJ: Hypnotica		http://virtualdjradio.com:8000/channel3.mp3
Virtual DJ: PowerBase		http://virtualdjradio.com:8000/channel4.mp3
Radio Free Americana		http://thassos.cdnstream.com:5479/live
Venice Classic Radio Italia	http://116.202.241.212:8010/;
Radio Swiss Jazz		http://stream.srg-ssr.ch/m/rsj/mp3_128
Tropicalisma FM			http://tropicalisima.org:9002/;
Jamendo Lounge			http://streaming.radionomy.com/JamendoLounge
Rockabilly Radio		http://lin3.ash.fastserv.com:6026/stream_96
Dandelion Radio			http://streamz.anytek.co.uk/proxy/dandelio2?mp=/stream
Splinterwood			http://31.3.245.162:8000/;
--
--
--
--
--
--
--
--

BBC World Service		https://stream.live.vc.bbcmedia.co.uk/bbc_world_service
Classic FM			http://media-ice.musicradio.com/ClassicFMMP3
Classic FM - Movies		http://media-ice.musicradio.com/ClassicFM-M-Movies
Classic FM - Relax		http://media-the.musicradio.com/ClassicFM-M-Relax
Classic Rock			http://media-the.musicradio.com/RadioXClassicRockMP3
Big Top 40			http://media-the.musicradio.com/BigTop40MP3
--
Radio North Sea Int'l		http://radionorthsea.zapto.org:8008/stream
Nashville FM			http://server-14.stream-server.nl:8300/;
Country Power Station		http://shoutcast.countrypowerstation.net:8000/;
BlackBeats FM			http://rautemusik-de-hz-fal-stream12.radiohost.de/blackbeats
WZUP WRLD			http://usa17.fastcast4u.com/proxy/nczrhanc?mp=/1
--
--
--
--
--
--
--
--

Radio El Dorado			http://el-dorado.stream.laut.fm/el-dorado
Asia Dream Jazz			http://kathy.torontocast.com:3330/;
Streaming Sound Tracks		http://hi5.streamingsoundtracks.com/;
Tiki Bar Radio			http://live.rcast.net:8522/;
Radio Mi Amigo Int'l		http://lion.radioca.st/;
Nagaswara FM			http://jakarta.nagaswarafm.com:8088/stream
Radio Paloma			http://stream.silvacast.com/RPLive/mp3-128/radio_de
Ballermann Radio		http://stream.bmr-radio.de/ballermann-radio.mp3
SRC FM				http://cc6.beheerstream.com/proxy/src1?mp=/stream;stream.mp3
Company Radio			http://sphera.fluidstream.eu/company.aac
Rahva Radio			http://streamer.tt.ee:8000/rahvaraadio
Death FM			http://hi.death.fm/;
--
--
--
--
--
--
--
--

`);

// Internet TV

var request_iptv = function (src, url, frame, fmt)
{
  if (src == "0") request (url, frame, -fmt);
  if (src == "1") request ("@" + url, frame, -fmt);

  if (src == "6")  open_tv0 (frame, 1, url, 0);  // DASH
  if (src == "7")  open_tv0 (frame, 0, url, fmt);
  if (src == "8")  open_tv0 (frame, 1, url, fmt);
  if (src == "9")  open_tv0 (frame, 0, url, 0);  // mp4, webm, etc.

  if (src == "1a") open_tv1 (frame, 2, url, fmt, src);  // tv247.us
  if (src == "1b") open_tv1 (frame, 3, url, fmt, src);  // tv247.us
  if (src == "1c") open_tv1 (frame, 0, url, fmt, src);  // tv247.us
  if (src == "1e") open_tv1 (frame, 1, url, fmt, src);  // content.uplynk.com
  if (src == "1f") open_tv1 (frame, 1, url, fmt, src);  // frankspeech.com
  if (src == "1p") open_tv1 (frame, 1, url, fmt, src);  // Pluto TV
  if (src == "1x") open_tv1 (frame, 1, url, fmt, src);  // Olympics

  if (src == "3a") open_tv3 (frame, 1, url, fmt, "http://www.freeintertv.com");
  if (src == "4a") open_tv4 (frame, 0, url, fmt, "http://streamw.ink");
  if (src == "5a") open_tv5 (frame, 0, url, fmt, "https://thetvapp.to");
  if (src == "6a") open_tv6 (frame, 1, url, fmt, "https://therokuchannel.roku.com");
  if (src == "7a") open_tv7 (frame, 1, url, fmt, "https://watch.plex.tv");
  if (src == "9a") open_tv9 (frame, 1, url, fmt, "https://www.distro.tv");
}
////////////////////

const open_tv0 = async (frame, mode, url, fmt) =>
{
  var n, f = [0,0,0,0], u = url.split ("<>"); if (is_busy (frame)) return;

  for (n = 0; n < u.length; n++) if ((url = u[n])[0] == "*") url = u[n] =
    cors_local ? cors_local + "~" + url : url.substr ((url.indexOf ("*", 1) + 1) || 1);

  if (!fmt)
  {
    if (mode & 1) stream_all (frame, 2); else fmt = undefined;
  }
  else if (u.length > 1)
  {
    stream_all (frame, 1); for (n = 0; n < 4; n++) if (u[n]) f[n] = 1;
    fixformat (f, frame); n = gotformat (f, fmt); url = u[n]; fmt = pixformat (n);
  }
  else if (stream_all (frame, 1) || !(mode & 1)) fmt = 0; else try
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (response.url, textData, frame, fmt);
  }
  catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame)) loadwindow (url, frame, "@", "", fmt);
}
////////////////////

const open_tv1 = async (frame, mode, url, fmt, src) =>
{
  var n, p, s, sub = src + "," + url; if (is_busy (frame, "", mode & 2)) return;

try
{
  if (src == "1a") url = "*http://tv247.us,,ts*http://live.tv247us.com/hls/" + url + ".m3u8";
  if (src == "1b") url = "*http://tv247.us,,*http://cdn.tv247.us/channel/" + url + ".m3u8";

  if (src == "1c")
  {
    response = await kitty (cors_bypass + "http://tv247.us/watch/" + url);
    textData = await response.text();

    url = pullstring (textData, 'var link= "', '"'); if (!url) throw ("!!!");
  }

  if (src == "1e") url = "https://content.uplynk.com/channel/" + url + ".m3u8";
  if (src == "1p") url = "*,,*https://stitcher.pluto.tv/stitch/hls/channel/" + url + "/master.m3u8" +
    "?appName=web&appVersion=na&deviceVersion=na&deviceDNT=na&deviceMake=na&deviceModel=na" +
    "&deviceType=na&deviceId=na&sid=na";

  if (src == "1x") if (url == "olympic")
  {
    url = "https://olympics.com/tokenGenerator?url=https://ott-dai-oc.akamaized.net/OC1/master.m3u8&domain=";

    response = await kitty (cors_bypass + url);
    textData = await response.text();

    url = pullstring (textData, '"', '"'); if (!url) throw ("!!!");
  }

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) open_tv0 (frame, mode, url, fmt);
}
////////////////////

const open_tv2 = async (frame, mode, url, fmt, src) =>
{
  var n, s, sub = "2," + url; if (is_busy (frame)) return;

if (s = stream_cache (sub)) url = s; else try
{

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) open_tv0 (frame, mode, url, fmt);
}
////////////////////

// http://www.freeintertv.com  format: ?????
const open_tv3 = async (frame, mode, url, fmt, src) =>
{
  var s, t, sub = "3," + url; if (is_busy (frame, "", 2)) return;

if (s = stream_cache (sub)) url = s; else try
{
  if (url.substr (0,3) != "id-") url = btoa (url); else
  {
    response = await kitty (cors_kraker + src + "/view/" + url);
    textData = await response.text();

    url = pullstring (textData, "<iframe", ">");
    url = pullstring (url, 'src="', '"'); if (!url) throw ("!!!");
    s = "TVSESS=" + pullstring (url, "TVSESS=", "");

    response = await kitty (cors_kraker + url, allow_cookie ("", s));
    textData = await response.text();

    url = pullstring (textData, 'data-path="', '"'); if (!url) throw ("!!!");

    response = await kitty (cors_kraker + "**" + src + "/" + url);
    textData = await response.text();

    url = pullstring (textData, 'data-path="', '"'); if (!url) throw ("!!!");
  }

  t = { 'content-type': 'application/x-www-form-urlencoded' };
  s = "chname=" + url + "&html5=11";

  url = cors_kraker + src + "/myAjax/get_item_m3u8/";

  response = await kitty (url, { method: 'POST', headers: t, body: s } );
  textData = await response.text();

  url = pullstring (textData, "='", "'");
  if (!url || url.includes (".cgtn.")) throw ("!!!"); stream_cache (sub, url, 0);

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) open_tv0 (frame, mode, url, fmt);
}
////////////////////

/*
4a:abc
4a:cnn
4a:cnninternational
4a:comedycentral
4a:fox10ksaz
4a:foxnews
*/

// http://streamw.ink
const open_tv4 = async (frame, mode, url, fmt, src) =>
{
  var n, s, sub = "4," + url; if (is_busy (frame), "", 2) return;

if (s = stream_cache (sub)) url = s; else try
{
  url = cors_kraker + "**" + src + "/0x10x00xxs101xsdwx0101001xs/" + url + ".phtml";

  response = await kitty (url);
  textData = await response.text();

  url = pullstring (textData, 'whistler = "', '"');
  url = pullstring (url, "http:", ""); if (!url) throw ("!!!");
  url = "*,,*http:" + url;

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) open_tv0 (frame, mode, url, fmt);
}
////////////////////

// https://thetvapp.to
const open_tv5 = async (frame, mode, url, fmt, src) =>
{
  var s, t, u, sub = "5," + url; if (is_busy (frame)) return;

if (s = stream_cache (sub)) url = s; else try
{
  response = await kitty (cors_bypass + src + "/tv/" + url, allow_cookie ("", ""));
  textData = await response.text();

  s = response.headers.get ("zz-set-cookie") || "";
  s = (t = "thetvapp_session=") + pullstring (s, t, ";") + "; " + (t = "XSRF-TOKEN=") + pullstring (s, t, ";");
  u = pullstring (textData, '"stream_name" name="', '"'); if (!u) throw ("!!!");
  u = cors_bypass + src + "/token/" + u;

  response = await kitty (u + "?quality=sd", allow_cookie ("", s));
  textData = await response.text(); t = pullstring (textData, '"url":"', '"');

  response = await kitty (u + "?quality=hd", allow_cookie ("", s));
  textData = await response.text(); u = pullstring (textData, '"url":"', '"');

  url = (t + "<><>" + u).replace (/\\/g, ""); if (!t && !u) throw ("!!!"); stream_cache (sub, url, 0);

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) open_tv0 (frame, mode, url, fmt);
}
////////////////////

// https://therokuchannel.roku.com  format: #####
const open_tv6 = async (frame, mode, url, fmt, src) =>
{
  var n, p, q, r, s, sub = "6," + url; if (is_busy (frame, "", 2)) return;

if (s = stream_cache (sub)) url = s; else try
{
  s = cors_local ? "/**" : "";

  response = await kitty (us_geo_bypass + src + "/watch/" + url, allow_cookie ("", s));
  textData = await response.text();

  p = response.headers.get ("zz-set-cookie") || ""; p = pullstring (p, "_csrf=", ";");
  q = pullstring (textData, 'csrf: "', '"'); if (!p || !q) throw ("!!!");

  q = { accept: "**" + s + "_csrf=" + p, 'content-type': 'application/json', 'csrf-token': q };

  r = JSON.stringify ({ mediaFormat: 'm3u', rokuId: url });
  r = { method: 'POST', body: r, headers: q };

  response = await kitty (us_geo_bypass + src + "/api/v3/playback", r);
  textData = await response.text(); url = pullstring (textData, '"url":"', '&');

  if (!url) throw ("!!!"); stream_cache (sub, url, 0);

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) open_tv0 (frame, mode, url, fmt);
}
////////////////////

// https://watch.plex.tv/live-tv  format: ?????
const open_tv7 = async (frame, mode, url, fmt, src) =>
{
  var h, s, t, sub = "7," + url; if (is_busy (frame, "", 2)) return;

if (s = stream_cache (sub)) url = s; else try
{
  s = { accept: 'application/json', 'X-Plex-Product': 'Plex Mediaverse', 'X-Plex-Client-Identifier': 'x' };

  response = await kitty (cors_kraker + "https://plex.tv/api/v2/users/anonymous", { method: 'POST', headers: s });
  textData = await response.text(); if (!(t = pullstring (textData, '"authToken":"', '"'))) throw("!!!");

  response = await kitty ("!" + cors_kraker + src + "/en-GB/live-tv/" + url);
  textData = await response.text();

  s = pullstring (textData, '\\"slug\\":\\"' + url + '\\"', '.m3u8');
  s = pullstring (s, '\\"key\\":\\"', ''); if (!s) throw ("!!!");

  url = cors_kraker + "*,,*https://epg.provider.plex.tv" + s + ".m3u8?X-Plex-Token=" + t;

  stream_cache (sub, url, 0);

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) open_tv0 (frame, mode, url, fmt);
}
////////////////////

const open_tv8 = async (frame, mode, url, fmt, src) =>
{
  var n, s, sub = "8," + url; if (is_busy (frame, "", 2)) return;

if (s = stream_cache (sub)) url = s; else try
{

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) open_tv0 (frame, mode, url, fmt);
}
////////////////////

// view-source:https://www.distro.tv/live format: ?????
const open_tv9 = async (frame, mode, url, fmt, src) =>
{
  var n, s, sub = "9," + url; if (is_busy (frame)) return;

if (s = stream_cache (sub)) url = s; else try
{
  url = src + "/live/" + url + "/";

  response = await kitty (cors_bypass + url);
  textData = await response.text();

  url = pullstring (textData, '"contentUrl":"', '"');
  n = url.indexOf ("&url=http"); if (n > 0) url = url.substr (n + 5);
  n = url.indexOf ("?"); if (n > 0) url = url.substr (0, n);

  if (!url) throw ("!!!"); stream_cache (sub, url, 0);

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) open_tv0 (frame, mode, url, fmt);
}
////////////////////

