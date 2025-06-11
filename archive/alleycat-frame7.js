// Free Movies & TV

document.getElementById ("src7").innerHTML = `
  <option value= "youtube" class="w">YouTube MP4 / WEBM
  <option value= "tubitv"     ># m3u - Tubi
  <option value= "thearchive" >+ mp4 - The Archive
  <option value= "darkmatter" >? m3u - Dark Matter
  <option value= "fawesome"   ># m3u - Fawesome
  <option value= "filmzie"    >+ m3u - Filmzie
  <option value= "plextv"     >? m3u - Plex
  <option value= "bilibili"   ># mpd - Bilibili
  <option value= "goojara"    ># mp4 - Goojara
  <option value= "ridomovies" >+ m3u - RidoMovies
  <option value= "soaper"     ># m3u - Soaper
  <option value= "wconline"   >? mp4 - WCOnline
  <option value= "yesmovies"  ># m3u - YesMovies
  <option value= "xhamster"   ># mp4 - XHamster
  <option value= "xvideos"    >? m3u - XVideos
  <option value= "autoembed"  class="w">@ mp4 - AutoEmbed
  <option value= "closeload"  class="b"># mp4 - CloseLoad
  <option value= "doodstream" class="b"># mp4 - DoodStream
  <option value= "dropload"   class="b"># m3u - DropLoad
  <option value= "eplayvid"   class="b"># mp4 - EplayVid
  <option value= "mixdrop"    class="b"># mp4 - MixDrop
  <option value= "moviesapi"  class="w">@ m3u - MoviesAPI
  <option value= "pkspeed"    class="b"># mp4 - PkSpeed
  <option value= "streamtape" class="b"># mp4 - StreamTape
  <option value= "turbovid"   class="b"># mp4 - TurboVid
  <option value= "upstream"   class="b"># m3u - UpStream
  <option value= "vidora"     class="w">@ mp4 - Vidora
  <option value= "vidsrc"     class="w">@ mp4 - VidSrc
  <option value= "vtube"      class="b"># mp4 - VTube
  <option value= "wootly"     class="b"># mp4 - Wootly
`;

document.getElementById ("butt7").innerHTML = `
  <button onclick="copylist(this,7,-1)">Music</button>
  &nbsp;
  <button onclick="copylist(this,7,-2)">TV US1</button>
  <button onclick="copylist(this,7,-3)">TV US2</button>
  <button onclick="copylist(this,7,-4)">TV US3</button>
  &nbsp;
  <button onclick="copylist(this,7,-5)">TV UK+</button>
  <button onclick="copylist(this,7,-6)">TV Alt</button>
  &nbsp;
  <button onclick="copylist(this,7,-7)">TV Int'l</button>
`;

table_7 = [
  "Tubi           m3u8      #   Proxy      https://tubitv.com",
  "The Archive    m3u8      +   No Proxy   https://www.thearchive.tv",
  "Dark Matter    m3u8      ?   KRKR       https://www.darkmattertv.com",
  "Plex           m3u8/mpd  +   Proxy      https://watch.plex.tv/on-demand",
  "Fawesome       m3u8      #   KRKR       https://fawesome.tv/home",
  "Filmzie        m3u8      #   Proxy      https://filmzie.com",
  "Bilibili       mpd       #   KRAK       https://www.bilibili.tv",
  "Goojara        mp4       #   KRAK       https://ww1.goojara.to",
  "RidoMovies     m3u       +   KRAK       https://ridomovies.tv",
  "Soaper         m3u8      #   KRAK       https://soaper.live  https://soaper.top",
  "WCOnline       mp4       ?   KRAK       https://www.wco.tv|!  https://www.wcofun.net|!",
  "YesMovies      m3u       #   KRAK       https://ww.yesmovies.ag",
  "XHamster       mp4       #$  KRAK       https://xhamster.com",
  "XVideos        m3u8/mp4  ?   Proxy      https://www.xvideos.com",
  "",
  "AutoEmbed      mp4       @$  KRAK       https://autoembed.cc",
  "CloseLoad      m3u8      #   KRAK       https://closeload.top",
  "DoodStream     mp4       #   KRAK       https://doodstream.com",
  "DropLoad       m3u8      #   KRAK       https://dropload.io",
  "EplayVid       mp4       #$  KRAK       |no site link",
  "MixDrop        mp4       #   KRAK       https://mixdrop.ag",
  "MoviesAPI      mp4       @   KRAK       https://moviesapi.club",
  "PkSpeed        mp4       #$  KRAK       https://pkspeed.net",
  "StreamTape     mp4       #   KRAK       https://streamtape.com",
  "TurboVid       mp4       #   KRAK       https://turbovid.eu",
  "UpStream       m3u8/mp4  #$  KRAK       https://upstream.to",
  "Vidora         mp4       @$  No Proxy   https://vidora.su",
  "VidSrc         mp4       @$  Proxy      https://vidsrc.co",
  "VTube          m3u8      #$  Proxy      https://vtube.network",
  "Wootly         mp4       #   KRAK       |no site link",
];

frame_7 = {
  req_youtube: request
}

stack_7_1 = copylist (`
  Company TV (Italy)			8:https://company.fluid.stream/CompanyTV/smil:Company_ALL.smil/playlist.m3u8
  Deejay TV (Italy)			8:http://4c4b867c89244861ac216426883d1ad0.msvdn.net/live/S85984808/sMO0tz9Sr2Rk/playlist.m3u8
  Ditty TV (US)				8:https://0ba805a2403b4660bbb05c0a210ebbdc.mediatailor.us-east-1.amazonaws.com/v1/master/04fd913bb278d8775298c26fdca9d9841f37601f/ONO_DittyTV/playlist.m3u8
  Kaloopy (US) *			9a:kaloopy
  KroneHit TV (Austria)			8:http://bitcdn-kronehit.bitmovin.com/v2/hls/index.m3u8
  Ocko Expres (Czech Republic)		8:http://ocko-live.ssl.cdn.cra.cz/channels/ocko_expres/playlist.m3u8
  Power HD (Turkey)			8:http://livetv.powerapp.com.tr/powerTV/powerhd.smil/playlists.m3u8
  Radio Capital (Italy)			8:http://4c4b867c89244861ac216426883d1ad0.msvdn.net/live/S35394734/Z6U2wGoDYANk/playlist.m3u8
  Radio Chanson (Russia)		8:http://chanson-video.hostingradio.ru:8080/hls/chansonabr/live.m3u8
  Radio m2o (Italy)			8:http://4c4b867c89244861ac216426883d1ad0.msvdn.net/live/S62628868/uhdWBlkC1AoO/playlist.m3u8
  Reload TV (Greece) ??			8:http://web.onair-radio.eu:1935/video/video/index.m3u8
  Retro Music (Czech Republic)		8:http://stream.mediawork.cz/retrotv/retrotvHQ1/playlist.m3u8
  Shuffle Dance Music (YouTube)		0:qWf-FPFmVw0
  Siganos Music (Greece)		8:http://web.onair-radio.eu:1935/Alpha-Host/Alpha-Host/playlist.m3u8
  Stingray Classica (Canada)		8:https://lotus.stingray.com/manifest/classica-cla008-montreal/samsungtvplus/master.m3u8
  Stringray CMusic (Canada)		8:https://lotus.stingray.com/manifest/cmusic-cme004-montreal/samsungtvplus/master.m3u8
  Stingray DJazz (Canada)		8:https://lotus.stingray.com/manifest/djazz-djaads-montreal/samsungtvplus/master.m3u8
  Stringray Qello (Canada)		8:https://lotus.stingray.com/manifest/qello-qello001-montreal/samsungtvplus/master.m3u8
  Strana FM (Russia)			8:http://live.stranafm.cdnvideo.ru/stranafm/smil:stranafm.smil/playlist.m3u8
  V2Beat (Germany)			8:http://stream.v2beat.live/playlist.m3u8
  Vevo Pop (US) **			1p:5d93b635b43dd1a399b39eee
  Visual Radio (Turkey)			8:http://wms.shared.streamshow.it/visualradio/mp4:visualradio/playlist.m3u8
`);

stack_7_2 = copylist (`
  ABC *					5a:wabc-new-york-abc-east-live-stream
  ABC News				1e:3324f2467c414329b3b0cc5cd987b6be
  AMC *					5a:amc-live-stream
  BBC America *				5a:bbc-america-live-stream
  Bloomberg				8:https://www.bloomberg.com/media-manifest/streams/phoenix-us.m3u8
  CBS *					5a:wcbs-new-york-cbs-east-live-stream
  CBS News				8:http://cbsn-us.cbsnstream.cbsnews.com/out/v1/55a8648e8f134e82a470f83d562deeca/master.m3u8
  CNBC *				5a:cnbc-live-stream
  CNN *					5a:cnn-live-stream
  C-SPAN *				5a:cspan-live-stream
  C-SPAN 2 *				5a:cspan-2-live-stream
  ET Live				8:https://dai.google.com/linear/hls/event/xrVrJYTmTfitfXBQfeZByQ/master.m3u8
  Fox *					5a:wnyw-new-york-fox-east-live-stream
  Fox Business *			5a:fox-business-network-live-stream
  Fox News *				5a:fox-news-channel-live-stream
  Fox News Now (YT)			0:YDfiTGGPYCk
  MSNBC *				5a:msnbc-live-stream
  NBC *					5a:wnbc-new-york-nbc-east-live-stream
  NBC News (YT)				1:UCeY0bbntWzzVIaj2z3QigXg
  PBS *					5a:pbs-13-wnet-new-york-live-stream
  PopStar!				8:https://linear-10.frequency.stream/dist/zype/10/hls/master/playlist.m3u8
  Sundance *				5a:sundancetv-hd-live-stream
  Syfy *				5a:syfy-live-stream
  TBS (East)				7:https://turnerlive.warnermediacdn.com/hls/live/2023172/tbseast/slate/VIDEO_2_1964000.m3u8
  TBS (West)				7:https://turnerlive.warnermediacdn.com/hls/live/2023174/tbswest/slate/VIDEO_2_1964000.m3u8
  The CW *				5a:the-cw-live-stream
  TMZ					8:https://d2dimalv43j51f.cloudfront.net/out/v1/52d3048e53eb42a7959dc347d2f810e2/index.m3u8
  TNT (East)				7:https://turnerlive.warnermediacdn.com/hls/live/2023168/tnteast/slate/VIDEO_2_1964000.m3u8
  TNT (West)				7:https://turnerlive.warnermediacdn.com/hls/live/2023170/tntwest/slate/VIDEO_2_1964000.m3u8
  Tru TV (East)				7:https://turnerlive.warnermediacdn.com/hls/live/2023176/trueast/slate/VIDEO_2_1964000.m3u8
  Tru TV (West)				7:https://turnerlive.warnermediacdn.com/hls/live/2023178/truwest/slate/VIDEO_2_1964000.m3u8
  USA Network *				5a:usa-network-live-stream
  WE TV *				5a:we-tv-live-stream
`);

stack_7_3 = copylist (`
  Adventure Sports *			9a:adventure-sports-tv
  America's Test Kitchen **		1p:5e84f54a82f05300080e6746
  Billiard TV *				9a:billiard-tv
  Boxing TV *				9a:boxing-tv
  Dot Esports *				9a:dot-esports
  Dungeon TV **^			7a:dungeon-tv-2
  Entrepreneur *			9a:entrepreneur-1
  Gusto TV *				9a:gusto-tv
  HGTV *				5a:hgtv-live-stream
  Hunt Channel ??			8:http://1111296894.rsc.cdn77.org/LS-ATL-56868-1/index.m3u8
  MMA Junkie *				9a:mma-junkie
  MotorTrend FAST TV			8:https://3fa797d5.wurl.com/master/f36d25e7e52f1ba8d7e56eb859c636563214f541/T05PX01vdG9yVHJlbmRGYXN0VFZfSExT/playlist.m3u8
  PGA Tour **				1p:5de94dacb394a300099fa22a
  Red Bull TV				8:http://rbmn-live.akamaized.net/hls/live/590964/BoRB-AT/master.m3u8
  Right Now TV *			9a:right-now-tv
  SpeedVision **^			7a:speedvision
  Sports Grid				8:https://sportsgrid-klowdtv.amagi.tv/hls/amagi_hls_data_klowdtvAA-sportsgrid-klowdtv/CDN/playlist.m3u8
  Tastemade				8:https://tastemade-xumo.amagi.tv/hls/amagi_hls_data_tastemade-tastemadefreetv16xumo/CDN/master.m3u8
  This Old House **			1p:5d51e791b7dba3b2ae990ab2
  Waypoint TV **^			7a:waypoint-tv
  World Poker Tour *			9a:world-poker-tour
  ESPN *				5a:espn-live-stream
  ESPN 2 *				5a:espn2-live-stream
  Fox Sports 1 *			5a:fox-sports-1-live-stream
  Fox Sports 2 *			5a:fox-sports-2-live-stream
  Golf Channel *			5a:golf-channel-live-stream
  NBA TV *				5a:nba-tv-live-stream/
  NBC Golf *				5a:golf-channel-live-stream
  NFL Network *				5a:nfl-network-live-stream
  NHL Network *				5a:nhl-network-live-stream
  Olympic Channel *			1x:olympic
  Tennis Channel *			5a:tennis-channel-live-stream
`);

stack_7_4 = copylist (`
  American Heroes *			5a:american-heroes-channel-live-stream
  American Kennel Club			8:https://install.akctvcontrol.com/speed/broadcast/138/desktop-playlist.m3u8
  Circle TV				8:http://circle-xumo.amagi.tv/playlist.m3u8
  Classic Arts Showcase			8:https://classicarts.akamaized.net/hls/live/1024257/CAS/master.m3u8
  Comedy Dynamics *			9a:comedy-dynamics
  Comet ??				1e:3e45c6b5354a40f787e0b2aadb0f5d6a
  Court TV ??				1e:6c0bd0f94b1d4526a98676e9699a10ef
  Dark Matter TV *			9a:dark-matter-tv
  DocuBay ??				8:https://stream.ads.ottera.tv/playlist.m3u8?network_id=3444
  Dove Channel *			9a:dove
  FTV Midnight Secrets			8:https://fash1043.cloudycdn.services/slive/_definst_/ftv_midnite_secrets_adaptive.smil/playlist.m3u8
  FX *					5a:fx-live-stream
  FX Movie *				5a:fx-movie-live-stream
  FXX *					5a:fxx-live-stream
  Galxy TV **^				7a:galxy-tv-2
  HBO East *				5a:hbo-east-live-stream
  HBO Signature *			5a:hbo-signature-live-stream
  Horror Machine *			9a:horror-machine
  Law & Crime				9a:law-crime
  Lifetime *				5a:lifetime-live-stream
  Lone Star *				9a:lone-star
  Paramount Movie Channel **		1p:5cb0cae7a461406ffe3f5213
  Paramount Network **			1p:5812bcc8237a6ff45d16c407
  Scream Factory **^			7a:scream-factory-tv
  The Archive				8:https://stream-us-east-1.getpublica.com/playlist.m3u8?network_id=74
  The Film Detective			8:https://cdn-uw2-prod.tsv2.amagi.tv/linear/amg01201-cinedigmenterta-filmdetective-cineverse/playlist.m3u8
  The Pet Collective **^		7a:the-pet-collective-2
  Unexplained **^			7a:unexplained
`);

stack_7_5 = copylist (`
  BBC News *				3a:bbcnews_live
  Sky News Int'l **			1p:55b285cd2665de274553d66f
  Sky News Arabia			8:^https://slh/moc.aibaraswenyks.maerts/sna.m3u8
  France 24 - English (YT)		0:Ap-UM1O9RBU
  France 24 - French (YT)		0:l8PMl7tUDIE
  France 24 - Arabic (YT)		0:VuYzy8IuT0Y
  ABC News (Australia)			8:https://abc-news-dmd-streams-1.akamaized.net/out/v1/701126012d044971b3fa89406a440133/index.m3u8
  CBC News (Canada)			8:https://apollo.production-public.tubi.io/live/ac-cbc2.m3u8
  Global News				8:^https://lmsi.evil/7f0d3f550165-66d8-f034-3201-f7e19a94/evil/dpuorg/moc.vedlatigidsuroc.evil/.m3u8
  Newfoundland TV			8:https://2-fss-1.streamhoster.com/pl_122/201748-1431018-1/playlist.m3u8
  Knowledge Network (BC)		8:https://d1wal6k3d7ssin.cloudfront.net/out/v1/ea91db0906c847a4931b46a9ec36e77b/index.m3u8
  Ici RDI (CBC)				8:https://rcavlive.akamaized.net/hls/live/704025/xcanrdi/master.m3u8
  CPAC					8:https://d7z3qjdsxbwoq.cloudfront.net/groupa/live/f9809cea-1e07-47cd-a94d-2ddd3e1351db/live.isml/.m3u8
`);

stack_7_6 = copylist (`
  AfricaNews (YT)			0:NQjabLGdP5g
  Al Jazeera				8:https://live-hls-web-aje.getaj.net/AJE/index.m3u8
  Arirang (South Korea)			8:http://amdlive.ctnd.com.edgesuite.net/arirang_1ch/smil:arirang_1ch.smil/chunklist.m3u8
  CGTN News				7:https://english-livetx.cgtn.com/hls/yypdyyctzb_hd.m3u8
  Deutsche Welle			8:https://dwamdstream102.akamaized.net/hls/live/2015525/dwstream102/index.m3u8
  EuroNews *				9a:euronews
  GB News (UK, YT)			0:QliL4CGc7iY
  NHK World Japan			8:https://master.nhkworld.jp/nhkworld-tv/playlist/live.m3u8
  NTD (New Tang Dynasty)		8:https://ntd02.akamaized.net/NTDA/index.m3u8
  NDTV (India)				8:https://ndtv24x7elemarchana.akamaized.net/hls/live/2003678/ndtv24x7/ndtv24x7master.m3u8
  Press TV				8:https://live.presstv.ir/hls/presstv.m3u8
  RT News				8:https://rt-glb.rttv.com/live/rtnews/playlist.m3u8
  RT Documentary			8:https://rt-rtd.rttv.com/live/rtdoc/playlist.m3u8
  TeleSUR (YT)				0:qP2Gnp8I9sY
  TRT World				8:http://tv-trtworld.medya.trt.com.tr/master.m3u8
  World Is One News (India) *		9a:wion-world-is-one-news
  Blaze TV **				1p:5e46fba0c43b0d00096e5ac1
  Cheddar News				8:https://livestream.chdrstatic.com/b93e5b0d43ea306310a379971e384964acbe4990ce193c0bd50078275a9a657d/cheddar-42620/cheddarweblive/cheddar/index.m3u8
  Free Speech TV			8:https://edge.fstv-live-linear-channel.top.comcast.net/Content/HLS_HLSv3/Live/channel(b168a609-19c1-2203-ae1d-6b9726f05e67)/index.m3u8
  Lindell TV				8:https://rumble.com/live-hls-dvr/6rwx23/playlist.m3u8
  NewsMax *				5a:newsmax-tv
  NewsMax 2				8:https://nmxlive.akamaized.net/hls/live/529965/Live_1/index.m3u8
  OAN					8:https://a-cdn.klowdtv.com/live1/oan/playlist.m3u8
  OAN Plus *				9a:oan-encore
  Real America's Voice			8:https://dai.google.com/linear/hls/event/c-oMNcDLTeuszRKPugMj9Q/master.m3u8
  Salem Network				8:https://cdn-ue1-prod.tsv2.amagi.tv/linear/amg00732-salemmediagroup-snc-ono/playlist.m3u8
  The First TV				8:https://thefirst-oando.amagi.tv/hls/amagi_hls_data_thefirstd-thefirst-oando/CDN/playlist.m3u8
  TYT - The Young Turks			8:https://tyt-xumo-us.amagi.tv/hls/amagi_hls_data_tytnetwor-tyt-xumo/CDN/master.m3u8
  InfoWars - Main Feed			8:https://freespeech.akamaized.net/hls/live/2016712/live1/playlist.m3u8
  InfoWars - Alex Jones			8:https://freespeech.akamaized.net/hls/live/2024573/live2/playlist.m3u8
  InfoWars - Harrison Smith		8:https://freespeech.akamaized.net/hls/live/2016873/live3/playlist.m3u8
  InfoWars - Owen Shroyer		8:https://freespeech.akamaized.net/hls/live/2024574/live4/playlist.m3u8
`);

stack_7_7 = copylist (`
  EBS-1 (South Korea)			8:http://ebsonair.ebs.co.kr/groundwavefamilypc/familypc1m/master.m3u8
  EBS-2 (South Korea)			8:http://ebsonair.ebs.co.kr/ebs2familypc/familypc1m/index.m3u8
  EBS Kids (South Korea)		8:https://ebsonair.ebs.co.kr/ebsufamilypc/familypc1m/playlist.m3u8
  Thai PBS (Thailand) **^		8:**http://thaipbs-live.cdn.byteark.com/live/playlist.m3u8
  Kompas TV (Indonesia, YT)		0:DOOrIxw5xOw
  Public TV Armenia			8:https://amtvusdvr.tulix.tv/am2abr/index.m3u8
  Turkmenistan TV **			7:**http://alpha.tv.online.tm/hls/ch007_720/index.m3u8
  Zvezda TV (Russia)			8:http://tvchannelstream1.tvzvezda.ru/cdn/tvzvezda/playlist.m3u8
  TV Kujawy (Poland)			7:http://stream.tvkujawy.pl:8080/live/broadcast.m3u8
  FS1 Salzburg (Austria)		7:http://stream.fs1.tv:8080/hls/webstream.m3u8
  TV Filopoli (Greece)			8:http://live.streams.ovh:1935/tvfilopoli/tvfilopoli/playlist.m3u8
  Super TV (Italy)			8:http://wms.shared.streamshow.it:1935/supertv/supertv/live.m3u8
  TV 2000 (Italy)			8:https://hls-live-tv2000.akamaized.net/hls/live/2028510/tv2000/master.m3u8
  Wow! TV (El Salvador)			8:http://cdn.elsalvadordigital.com:1935/wowtv/wowtv/playlist.m3u8
  TV Lobo (Mexico)			8:http://streamingcws20.com:1935/lobodurango/videolobodurango/playlist.m3u8
`);

/*
  
9a:sonicentric
7a:midnight-pulp
7a:frightflix-2
7a:usa-today-news
7a:pickletv
7a:wildearth
7a:retrocrush
7a:asiancrush

  Stingray Classica (Canada) *		9a:stingray-classica
  Stingray Qello (Canada) *		9a:stingray-qello
  Law & Crime				6a:8ba514251e1a58b7b53368177baa1041

  OAN Encore				8:https://stream-us-east-1.getpublica.com/playlist.m3u8?&network_id=1879
  Salem Network				8:https://snc-ono.amagi.tv/playlist.m3u8
  Fox News **				7:*https://usnewson.com*https://s0.usnlive.com/stream/foxnews.m3u8
  MSNBC **				7:*https://usnewson.com*https://s0.usnlive.com/stream/msnbc.m3u8

  cnn international https://turnerlive.warnermediacdn.com/hls/live/586497/cnngo/cnni/VIDEO_0_3564000.m3u8
  australia abc  https://abc-news-dmd-streams-1.akamaized.net/out/v1/abc83881886746b0802dc3e7ca2bc792/index.m3u8
*/

frame_7.req_tubitv = async (id, frame, fmt) =>
{
  id = id.split ("?")[0].split ("/"); id = id [4] || id [0];

  var tag = "tubitv"; id = getid (frame, id, -9, -6);
  if (!id || is_busy (frame, tag + " (ID)", 0)) return;

  var s, t, url = "https://tubitv.com/movies/" + id;

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  s = pullstring (textData, '"video_resources":', '}],'); if (!s) throw ("!!!");
  url = ""; s = JSON.parse ('{"x":' + s + '}]}'); s = s.x;

  for (t of s) if (t.codec == "H264") if (!t.license_server) { url = t.manifest.url; break; } else
    if (t.type.includes ("widevine") && t.license_server.hdcp_version == "hdcp_disabled")
      url = t.manifest.url + "##" + t.license_server.url;

  if (!url) throw ("!!!"); else if (stream_all (frame, 1)) fmt = ""; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

  if (url.includes ("##")) tag += "-drm";

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_7.req_thearchive = async (id, frame, fmt) =>
{
  var tag = "thearchive"; id = getid (frame, id, -6);
  if (!id || is_busy (frame, tag + " (ID)", 0)) return;

  var url = cors_local + "https://api-ott.thearchive.tv/search";

try
{ 
  var s = { 'content-type':'application/x-www-form-urlencoded' };

  response = await kitty (url, { method: 'POST', headers: s, body: "id=" + id } );
  jsonData = await response.json();

  url = jsonData.objects[0].video_url; if (!url) throw ("!!!");

  if (stream_all (frame, 1)) fmt = ""; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_7.req_plextv = async (id, frame, fmt) =>
{
  var tag = "plextv"; id = getid (frame, id, 24);
  if (!id || is_busy (frame, tag + " (ID)", 0)) return;

  var s, t, u, sub, url, src = "https://vod.provider.plex.tv";

try
{ 
  s = { accept: 'application/json', 'X-Plex-Product': 'Plex Mediaverse', 'X-Plex-Client-Identifier': 'x' };
  response = await kitty (cors_bypass + "https://plex.tv/api/v2/users/anonymous", { method: 'POST', headers: s });
  textData = await response.text();

  u = "/library/metadata/" + id; if (!(t = pullstring (textData, '"authToken":"', '"'))) throw("!!!");
  url = src + "/playQueues?uri=provider://tv.plex.provider.vod" + u;

  s = { accept: 'application/json', 'X-Plex-Token': t };
  response = await kitty (cors_bypass + url, { method: 'POST', headers: s });
  jsonData = await response.json();

  sub = ""; for (s of jsonData.MediaContainer.Metadata) if (s.key == u) { sub = s.Media; break; }
  if (!sub) throw ("!!!"); s = sub[0].Part[0]; if (s.license) s = sub[1].Part[0];
  t = "?X-Plex-Token=" + t; url = src + s.key + t;

  if (u = s.license)
  {
    tag += "-drm"; stream_all (frame, 2); fmt = 0;
    url += "##" + src + u + t + "&X-Plex-DRM=widevine";
  }
  else if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_7.req_bilibili = async (id, frame, fmt) =>
{
  var tag = "bilibili"; id = getid (frame, id.split ("?")[0], 16);
  if (!id || is_busy (frame, tag + " (ID)", 2)) return;

  var url = "https://api.bilibili.tv/intl/gateway/web/playurl?platform=web&aid=" + id;
  var n, r, s, t, f = [0,0,0,0], u = [];

try
{
  response = await kitty (cors_kraker + url);
  jsonData = await response.json();

  if (!(url = jsonData.data.playurl)) throw ("!!!");

  if (t = url.video) for (n = 0; n < t.length; n++)
    if ((s = t [n].video_resource) && s.codec_id == 7 && s.url)
    {
      r = [ s.codecs, s.segment_base.range, s.segment_base.index_range, s.url ];
      s = t [n].stream_info.desc_words;

      if (s == "360P") { u.push (r); f [0] = u.length; }
      if (s == "480P") { u.push (r); f [1] = u.length; }
      if (s == "720P") { u.push (r); f [2] = u.length; }
    }

  if (!(t = url.audio_resource) || !(s = t [0]) || !s.url) throw ("!!!");
  t = [ s.codecs, s.segment_base.range, s.segment_base.index_range, s.url ];

  fmt = argformat (getformat (f, fmt)); if (fmt < 0) throw ("!!!");
  s = u [f [fmt] - 1]; fmt = pixformat (fmt);

  r = cors_kraker + "~*https://www.bilibili.tv/*";

  download = "Bilibili DASH download links (" + id + ") -- " +
    "<a href='" + r + t[3] + "'>Audio</a> &nbsp;" +
    "<a href='" + r + s[3] + "'>Video</a>";

//  t[3] = "biliaud.mp4"; s[3] = "bilivid.mp4"; 

  r = (url.duration / 1000) + "|audio/mp4|" + t[0] + "|video/mp4|" + s[0] + "|" +
      t[1] + "," + t[2] + "," + s[1] + "," + s[2] + "|bili.mpd|" + t[3] + "|" + s[3] + "|" + r;

  await kitty ("/wanna_boot_dash", { method: 'POST', body: r });
  stream_all (frame, 2); url = cors_kraker + "_wanna_boot_dash_bili.mpd";

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_7.req_fawesome = async (id, frame, fmt) =>
{
  if (id.includes ("/")) id = id.split ("/")[4];
  var tag = "fawesome"; id = getid (frame, id, 8);
  if (!id || is_busy (frame, tag + " (ID)", 1)) return;

  var s, t, url, src = "https://fawesome.tv/";
  var query = "**" + src + "home/new/v404/api/XXX.php?appId=9&siteId=236&auth-token=1217575";

try
{
  if (!(t = cookies [tag]))
  {
    response = await kitty (cors_kraker + query.replace ("XXX", "getSecurityToken"));
    textData = await response.text();

    t = pullstring (textData, '"securityToken":"', '"');
    if (!t) throw ("???"); s = { headers: { token: t }};

    response = await kitty (cors_kraker + query.replace ("XXX", "index"), s);
    textData = await response.text();

    s = pullstring (textData, '"countryCode":"', '"') || "US"; t = cookies [tag] = t + " " + s;
  }

  t = t.split (" "); s = { headers: { token: t[0] }};
  t = "&searchType=nodeid&country=" + t[1] + "&nid=" + id;

  response = await kitty (cors_kraker + query.replace ("XXX", "recipes") + t, s);
  textData = await response.text();

  url = pullstring (textData, '"video_hls_url":"', '"'); if (!url) throw ("!!!");
  url = url.replace (/\\/g, "");
  
  if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_7.req_filmzie = async (id, frame, fmt) =>
{
  var tag = "filmzie"; id = getid (frame, id, 24);
  if (!id || is_busy (frame, tag + " (ID)", 0)) return;

  var url = "https://filmzie.com/api/v1/video/stream/" + id;

try
{
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  url = pullstring (textData, '"file":"', '"'); if (!url) throw ("!!!");
  
  if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_7.req_goojara = async (id, frame, fmt) =>
{
  var tag = "goojara"; id = getid (frame, id, 8, 6);
  if (!id || is_busy (frame, tag + " (ID)", 2)) return;

  var c, s, url = "https://ww1.goojara.to/" + id;

if (id.length == 8) url = id; else try
{
  response = await kitty (cors_kraker + url, allow_cookie (tag, ""));
  textData = await response.text();

  if (response.status == 403)
  {
    url = pullstring (url, "//", "/") + "/robots.txt";
    cookiecutter (url + "=" + tag); busy = 0; no_fail (frame, id); return;
  }

  url = pullstring (textData, 'Direct Links:', 'Wootly');
  url = pullstring (url, 'href="', '"'); if (!url) throw ("!!!");

  s = pullstring (textData, "<script\>", "</script\>");
  s = pullstring (s, "('", "')").split ("','");

//  s = "var cookie='';" + s.replace (/document[^=^\)]*/g, "cookie") + "s=cookie";
//  eval (s);

  c = response.headers.get ("zz-set-cookie") || "";
  c = pullstring (c, "", ";") + "; " + s[0] + "=" + s[1];
  s = cookies [tag] || ""; if (s) c += "; " + s;

  response = await kitty (cors_kraker + url, allow_cookie ("", c));
  textData = await response.text();

  url = response.headers.get ("zz-location"); if (!url) throw ("!!!");

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame, id)) frame_7.req_wootly (url, frame, fmt);
}
////////////////////

frame_7.req_ridomovies = async (id, frame, fmt) =>
{
  if (id.replace (/\d/g, "")) { frame_7.req_closeload (id, frame, fmt); return; }

  var tag = "ridomovies"; id = getid (frame, id, -6);
  if (!id || is_busy (frame, tag + " (ID)", 2)) return;

  var src = "https://ridomovies.tv", url = src + "/api/episodes/" + id;

try
{
  response = await kitty (cors_kraker + "**!mock:1A|*" + url);
  textData = await response.text();

  url = pullstring (textData, 'data-src=\\"', '\\/\\"');
  url = url.replace (/\\/g, ""); if (!url) throw ("!!!");

  response = await kitty (cors_kraker + "*" + src + "/*" + url);
  textData = await response.text();

  url = pullstring (textData, 'file:"', '"');
  if (!url) throw ("!!!"); url = cors_kraker + "*,,*" + url;

  if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_7.req_soaper = async (id, frame, fmt) =>
{
  var tag = "soaper", tv = id.split ("/").pop(); id = getid (frame, tv, 10);
  if (!id || is_busy (frame, tag + " (ID)", 2)) return;

  tv = tv.split ("_")[0]; if (tv != "episode") tv = "";
  var src = "https://soaper.live", url = src + "/home/index/Get" + (tv ? "E" : "M") + "InfoAjax";

try
{
  var b = "pass=" + id + "&param=&extra=0.0.0.0&e2=1&server=0";

  var h = { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' };

  response = await kitty (cors_kraker + "**" + url, { method: 'POST', headers: h, body: b });
  jsonData = await response.json();

  url = jsonData.val; if (!url) throw ("!!!"); stream_all (frame, 1);
  url = cors_kraker + "~*~/,m3u8,*" + src + url.replace ("?", ".m3u8?");

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, (tv ? tv + "_" : "movie_") + id);
}
////////////////////

frame_7.req_yesmovies = async (id, frame, fmt) =>
{
  var tag = "yesmovies", url = id.split ("/"), ep = url.pop(), ss = url.pop();
  if (!ss || !ep || ss.length > 2 || ep.length > 2) ss = ""; else id = url.pop();

  if (!(id = getid (frame, id, -10, -7, 4)) || is_busy (frame, tag + " (ID)", 2)) return;
  var s, t, u, src = "https://movuna.xyz", ref = "*https://ww.yesmovies.ag/,,*";

try
{
  s = id + "+" + (ss ? ep : "1") + "+1+" + Math.trunc (Date.now() / 1000);
console.log(s);
  t = [190,108,254,121,21,177,48,122,146,60,250,89,224,19,54,64,56,239,104,206,177,233,175,223,238,214,7,82,176,70,184,72];

  u = Array.from (await pussyfoot ("AES-ENC-GCM=256=!=" + bin2hex (t), s));
  u = "0000000000000000-000000000000000000000000-" + bin2hex (u.slice (32).concat (u.slice (16,32)));

  response = await kitty (cors_kraker + ref + src + "/get/" + u);
  textData = await response.text();

  url = pullstring (textData, '"info":"', '"'); if (!url || url.includes (" ")) throw ("!!!");
  stream_all (frame, 1); url = cors_kraker + "~" + ref + "range=|*" + src + "/hls/" + url + "/master.m3u8";

} catch (err) { console.log (err); busy = 0; }

  if (ss) id += "/" + ss + "/" + ep;
  if (no_fail (frame, id)) loadwindow (url, frame, tag, id);
}
////////////////////

frame_7.req_xhamster = async (id, frame, fmt) =>
{
  var tag = "xhamster"; id = getid (frame, id, -8);
  if (!id || is_busy (frame, tag + " (ID)", 2)) return;

  var url = "https://xhamster.com/embed/" + id;
  var i, j, k, f = [0,0,0,0], r = [0,0,0,0];

if (stream_all (frame, 0)) fmt = ""; else try
{
  response = await kitty (cors_kraker + url);
  textData = await response.text();

  var s = '"standard":';
  var n = textData.indexOf (s); if (n < 0) throw ("!!!");
  var sub = textData.substr (n + s.length);
  sub = sub.substr (0, sub.indexOf ("}]}") + 3);
  sub = JSON.parse (sub); sub = sub.h264;

  for (i = 0; i < sub.length; i++)
  {
    k = sub[i].quality; k = k.substr (0, k.indexOf ("p")); if (!k) continue;
    if ((j = chkformat (k)) >= 0) if (r[j] < k) { f[j] = i + 1; r[j] = k; }
  }

  fmt = getformat (f, fmt); fixformat (f, frame);
  if ((j = argformat (fmt)) < 0 || (n = f[j] - 1) < 0) throw ("!!!");

  fmt = r[j]; url = sub[n].url;
  if (url.indexOf (".xhcdn.") < 0) url = sub[n].fallback;
  if (url.indexOf (".xhcdn.") < 0) throw ("!!!");
  url = cors_kraker + "~**" + url;

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_7.req_autoembed = async (id, frame, fmt) =>
{
  var t, u, src = "https://player.autoembed.cc";

  var tag = "autoembed", url = id.split ("/"), ep = url.pop(), ss = url.pop();
  if (!ss || !ep || ss.length > 2 || ep.length > 2) ss = ""; else id = url.pop();

  if (!(id = getid (frame, id, -10, -7, -4, 1)) || is_busy (frame, tag + " (ID)", 1)) return;
  t = ss ? "tv" : "movie"; id += (ss ? "/" + ss + "/" + ep : ""); url = src + "/embed/" + t + "/" + id;

if (stream_all (frame, 0)) fmt = ""; else try
{
  src = "https://nono.autoembed.cc"; url = src + "/api/getVideoSource?type=" + t + "&id=" + id;

  response = await kitty (cors_kraker + "**" + url);
  textData = await response.text();

  url = src + "/api/decryptVideoSource"; u = { 'content-type': 'application/json' };

  response = await kitty (cors_kraker + "**" + url, { method: 'POST', headers: u, body: textData });
  textData = await response.text();

  url = pullstring (textData, '"videoSource":"', '"'); if (!url) throw ("!!!");

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id);
}
////////////////////

frame_7.req_closeload = async (id, frame, fmt) =>
{
  var tag = "closeload"; id = getid (frame, id, 11);
  if (!id || is_busy (frame, tag + " (ID)", 2)) return;

  var s, sub, src = "https://closeload.top", url = src + "/video/embed/" + id;

try
{
  response = await kitty (cors_kraker + "**" + url);
  textData = await response.text();

  sub = pullstring (textData, s = "(p,a,c,k,e,d)", "<\/script>"); if (!sub) throw ("!!!");

  eval ("(sub=function" + s + sub); s = pullstring (sub, '});var', '";');
  url = atob (pullstring (s, '"', '')); if (!url) throw ("!!!");

  url = cors_kraker + "~*" + src + "/,m3u8,ts*range=|*" + url + ".m3u8";

  if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_7.req_doodstream = async (id, frame, fmt) =>
{
  var tag = "doodstream"; id = getid (frame, id, 12);
  if (!id || is_busy (frame, tag + " (ID)", 2)) return;

  var src = "https://dood.pm", url = src + "/d/" + id;

try
{
  response = await kitty (cors_kraker + "!mock:1A|*" + url);
  textData = await response.text();

  var s = pullstring (textData, '/download/', '"'); if (!s) throw ("!!!");
  await getmessage (1); url = src + "/download/" + s;

  response = await kitty (cors_kraker + "!mock:1A|*" + url);
  textData = await response.text();

  url = pullstring (textData, '</span> <a href="', '"'); if (!url) throw ("!!!");
  url = cors_kraker + "~**" + url;

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id);
}
////////////////////

frame_7.req_dropload = async (id, frame, fmt) =>
{
  var tag = "dropload"; id = getid (frame, id, 12);
  if (!id || is_busy (frame, tag + " (ID)", 2)) return;

  var src = "https://dropload.io", url = src + "/" + id + ".html";
  var u = "*!/,,*user-agent=|accept=|accept-language=|accept-encoding=|*";

try
{
  response = await kitty (cors_kraker + u + url);
  textData = await response.text();

  var sub = pullstring (textData, "p,a,c,k,e,d", "<\/script>"); if (!sub) throw ("!!!");

  eval ("(sub=function(p,a,c,k,e,d" + sub);
  url = cors_kraker + u + pullstring (sub, 'file:"', '"');

  if (!url.includes (".m3u8") || stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id);
}
////////////////////

frame_7.req_eplayvid = async (id, frame, fmt) =>
{
  var tag = "eplayvid"; id = getid (frame, id, 15);
  if (!id || is_busy (frame, tag + " (ID)", 2)) return;

  var url = "https://eplayvid.net/watch/" + id;

if (stream_all (frame, 0)) fmt = ""; else try
{
  response = await kitty (cors_kraker + url);
  textData = await response.text();

  url = pullstring (textData, '<source src="', '"'); if (!url) throw ("!!!");
  url = cors_kraker + "~**" + url;

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id);
}
////////////////////

frame_7.req_mixdrop = async (id, frame, fmt) =>
{
  var tag = "mixdrop"; id = getid (frame, id, -15, 5);
  if (!id || is_busy (frame, tag + " (ID)", 2)) return;

  var url = "https://mixdrop.ag/e/" + id;

try
{
  response = await kitty (cors_kraker + url);
  textData = await response.text();

  n = textData.indexOf ("p,a,c,k,e,d"); if (n < 0) throw ("!!!");

  var sub = textData.substr (n - 9, 1000);
  sub = sub.substr (0, sub.indexOf ("script") - 4); if (!sub) throw ("!!!");
  eval ("sub=" + sub); url = sub.substr (sub.indexOf ("wurl=") + 6);
  url = url.substr (0, url.indexOf ('"')); if (!url) throw ("!!!");
  url = cors_kraker + "~https:" + url;

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id);
}
////////////////////

frame_7.req_moviesapi = async (id, frame, fmt) =>
{
  var r, s, t, src = "https://moviesapi.club";

  var tag = "moviesapi", url = id.split ("/"), ep = url.pop(), ss = url.pop();
  if (!ss || !ep || ss.length > 2 || ep.length > 2) ss = ""; else id = url.pop();

  if (!(id = getid (frame, id, -10, -7, -4, 1)) || is_busy (frame, tag + " (ID)", 2)) return;
  url = src + "/" + (ss ? "tv/" : "movie/") + id + (ss ? "-" + ss + "-" + ep : "");

try
{
  response = await kitty (cors_kraker + "**" + url);
  textData = await response.text();

  url = pullstring (textData, "<iframe", '>');
  url = pullstring (url, 'src="', '"'); if (!url) throw ("!!!");

  if (url [0] == "/" && (url = "https:" + url))
  {
    response = await kitty (cors_kraker + "**" + url);
    textData = await response.text();

    s = pullstring (textData, "src: '", "'"); if (!s) throw ("!!!");
    t = url.split ("/").slice (0,3).join ("/");

    response = await kitty (cors_kraker + "**" + (s[0] == "/" ? t : "") + s);
    textData = await response.text(); url = pullstring (textData, "file: '", "'");
    if (url) url = cors_kraker + "~*" + t + "/,,*" + url;
  }
  else
  {
    url = url.replace ("https:", "http:"); t = url.split ("/")[2];

    r = 'shit = XMLHttpRequest.prototype.open; XMLHttpRequest.prototype.open = function(a,b)\n' +
        '{if (b.includes(".m3u8")) parent.parent.postMessage("@" + b, "*"); else shit.apply(this,arguments);}';

    s = 'var start = async () =>\n{\n' +
        '  if (location.hostname != "' + t + '") return;\n' +
        '  var m, n, resp = await fetch ("?"), data = await resp.text();\n' +
        '  n = data.indexOf ("<script"); m = \'\\n<script src="?@@~//.js"><\\/script>\\n\';\n' +
        '  data = data.substr (0, n) + m + data.substr (n); m = window.frames [0];\n' +
        '  m = m.document; m.open(); m.write (data); m.close();\n}\n';

    s = '<!DOCTYPE html><html><body onload="start()"><script>\n' + s +
        '<\/script><iframe></iframe></body></html>';

    await kitty ("/~wanna_scratch=/.js",  { method: 'POST', body: r });
    await kitty ("/~wanna_scratch=/.htm", { method: 'POST', body: s });

    t = stream_player (frame); t.style.visibility = "hidden"; t.src = url + "?@@~//.htm";
    url = await getmessage (15); t.src = ""; await getmessage (0.5); t.style.visibility = "";
    if (url) url = cors_kraker + "~*~,,*user-agent=abc|*" + url;
  }

  if (!url) throw ("!!!"); else if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (ss) id += "/" + ss + "/" + ep;
  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_7.req_pkspeed = async (id, frame, fmt) =>
{
  var tag = "pkspeed"; id = getid (frame, id, 12);
  if (!id || is_busy (frame, tag + " (ID)", 2)) return;

  var src = "https://pkspeed.net", url = src + "/embed-" + id + ".html";
  var n, s, t, f = [0,0,0,0];

if (stream_all (frame, 0)) fmt = ""; else try
{
  response = await kitty (cors_kraker + url);
  textData = await response.text();

  s = "(p,a,c,k,e,d)"; t = pullstring (textData, s, ")))"); if (!t) throw ("!!!");
  eval ("url=function" + s + t + "))"); s = pullstring (url, "sources:[", "]").split ("{");

  for (n = 1; n < s.length; n++)
  {
    t = pullstring (s [n], 'label:"', '"');
    if (t == "360p") f [0] = n;
    if (t == "480p") f [1] = n;
    if (t == "720p") f [2] = n;
  }

  fmt = getformat (f, fmt); fixformat (f, frame);
  n = argformat (fmt); fmt = pixformat (n); n = f [n];
  url = pullstring (s [n], '"', '"'); if (!url) throw ("!!!");
  url = cors_kraker + "~" + url;

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_7.req_streamtape = async (id, frame, fmt) =>
{
  var tag = "streamtape"; id = getid (frame, id, -15);
  if (!id || is_busy (frame, tag + " (ID)", 2)) return;
  var url = "https://streamtape.com/e/" + id;

try
{
  response = await kitty (cors_kraker + url);
  textData = await response.text();

  url = pullstring (textData, "substring(1).substring(2)", "<\/script>"); if (!url) throw ("!!!");
  url = pullstring (url, "&expires=", "')"); if (!url) throw ("!!!");
  url = "https://streamtape.com/get_video?id=" + id + "&expires=" + url;

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id);
}
////////////////////

frame_7.req_turbovid = async (id, frame, fmt) =>
{
  var tag = "turbovid"; id = getid (frame, id, 12,-10,-7);
  if (!id || is_busy (frame, tag + " (ID)", 2)) return;
  var n, r, s, t, u, src = "https://turbovid.me/", url = src + "embed/" + id;

if (stream_all (frame, 0)) fmt = 0; else try
{
  function decode (cipher, key)
  {
    for (n = 0, r = ""; n < cipher.length; n += 2)
      r += String.fromCharCode (parseInt (cipher.substr (n, 2), 16));

    for (n = 0, cipher = r, r = ""; n < cipher.length; n++)
      r += String.fromCharCode (cipher.charCodeAt (n) ^ key.charCodeAt (n % key.length));

    return (r.indexOf ("http") ? "" : r);
  }

  response = await kitty (cors_kraker + url);
  textData = await response.text();

  s = pullstring (textData, 'const apkey', ';'); t = pullstring (textData, 'const xxid', ';');
  s = pullstring (s, '"', '"'); t = pullstring (t, '"', '"'); if (!s || !t) throw ("!!!");

  url = "**" + src + "api/cucked/"; u = { headers: { 'X-Requested-With': 'XMLHttpRequest' }};

  response = await kitty (cors_kraker + url + "the_juice/?" + s + "=" + t, u);
  textData = await response.text();

  s = pullstring (textData, '"data":"', '"'); if (!s) throw ("!!!");

  response = await kitty (cors_kraker + url + "juice_key", u);
  textData = await response.text();

  t = pullstring (textData, '"juice":"', '"'); if (!t) throw ("!!!");
  url = decode (s, t); if (!url) throw ("!!!"); url = cors_kraker + "~*" + src + "*" + url;

  if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_7.req_upstream = async (id, frame, fmt) =>
{
  var tag = "upstream"; id = getid (frame, id, 12);
  if (!id || is_busy (frame, tag + " (ID)", 1)) return;

  var src = "https://upstream.to", url = src + "/embed-" + id + ".html";

if (stream_all (frame, 0)) fmt = ""; else try
{
  response = await kitty (cors_kraker + url);
  textData = await response.text();

  var n = textData.indexOf ("p,a,c,k,e,d"); if (n < 0) throw ("!!!");

  var sub = textData.substr (n - 9, 5000);
  sub = sub.substr (0, sub.indexOf ("script") - 4);
  eval ("sub=" + sub); url = pullstring (sub, 'file:"', '"'); if (!url) throw ("!!!");

  if (url[0] == "/") if (!(sub = pullstring (sub, 'image:"', '&'))) throw ("!!!"); else
  {
    n = url.indexOf ("&srv="); if (n > 0) url = url.substr (n); url = sub.split ("/")[2] + url;
  }

  if (!url.includes (".m3u8") || stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

  //url = cors_kraker + "~*" + src + "/,,*" + url;

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_7.req_vidora = async (id, frame, fmt) =>
{
  var e, r, s, t, src = "https://vidora.su";

  var tag = "vidora", url = id.split ("/"), ep = url.pop(), ss = url.pop();
  if (!ss || !ep || ss.length > 2 || ep.length > 2) ss = ""; else id = url.pop();

  if (!(id = getid (frame, id, -10, -7, -4, 1)) || is_busy (frame, tag + " (ID)", 0)) return;
  t = ss ? "tv" : "movie"; id += (ss ? "/" + ss + "/" + ep : ""); url = src + "/" + t + "/" + id;

if (stream_all (frame, 0)) fmt = ""; else if (!got_crypto()) busy = 0; else try
{
  var pe = btoa ("hope you had fun decrypting this good job now go ask your mom for a cookie");
  var fe = btoa ("omg you found my key please go touch grass you little fat basement monkey");

  r = Date.now(); s = Math.random().toString (36).substring (2, 15);

  e = CryptoJS.SHA256 (t + id + r + s + pe).toString();
  e = JSON.stringify ({ type: t, id: id, timestamp: r, random: s, checksum: e });
  e = JSON.stringify ({ data: CryptoJS.AES.encrypt (e, fe).toString(), timestamp: r });
  e = JSON.stringify ({ data: CryptoJS.AES.encrypt (e, fe + r).toString(), timestamp: r, random: s });
  e = CryptoJS.AES.encrypt (e, pe).toString();

  response = await kitty (cors_local + "https://stats.vidora.su", { headers: { 'x-auth': e }});
  textData = await response.text();

  e = pullstring (textData, '"encrypted":"', '"'); if (!e) throw ("!!!");

  e = JSON.parse (CryptoJS.AES.decrypt (e, pe).toString (CryptoJS.enc.Utf8));
  e = JSON.parse (CryptoJS.AES.decrypt (e.data, fe + e.timestamp).toString (CryptoJS.enc.Utf8));
  e = JSON.parse (CryptoJS.AES.decrypt (e.data, fe).toString (CryptoJS.enc.Utf8));

  url = e.data.sources[0].url; if (!url) throw ("!!!");

  if (url.includes (".m3u8"))
  {
    throw ("???");
    //url = cors_kraker + "~*" + src + "/,,*" + url; stream_all (frame, 1);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id);
}
////////////////////

frame_7.req_vidsrc = async (id, frame, fmt) =>
{
  var e, n, s, t, u, f = [0,0,0,0], src = "https://player.vidsrc.co";

  var tag = "vidsrc", url = id.split ("/"), ep = url.pop(), ss = url.pop();
  if (!ss || !ep || ss.length > 2 || ep.length > 2) ss = ""; else id = url.pop();

  if (!(id = getid (frame, id, -10, -7, -4, 1)) || is_busy (frame, tag + " (ID)", 1)) return;
  url = src + "/embed/" + (ss ? "tv/" + id + "/" + ss + "/" + ep : "movie/" + id);

if (stream_all (frame, 0)) fmt = ""; else if (!got_crypto()) busy = 0; else try
{
  url = src + "/api/server?sr=1&id=" + id + (ss ? "&ss=" + ss + "&ep=" + ep : "");

  response = await kitty (cors_kraker + "**" + url);
  textData = await response.text();

  s = pullstring (textData, '"data":"', '"'); if (!s) throw ("!!!");
  e = JSON.parse (atob (s)); s = CryptoJS.enc.Hex.parse (e.salt); t = CryptoJS.enc.Hex.parse (e.iv);

  u = CryptoJS.PBKDF2 (e.key, s, { keySize: 8, iterations: e.iterations, hasher: CryptoJS.algo.SHA256 });
  u = CryptoJS.AES.decrypt (e.encryptedData, u, { iv: t, mode: CryptoJS.mode.CBC });
  u = JSON.parse (u.toString (CryptoJS.enc.Utf8)); u = u.quality;

  for (n = 0; n < u.length; n++)
  {
    if (u[n].quality == "360P")  f[0] = n + 1;
    if (u[n].quality == "480P")  f[1] = n + 1;
    if (u[n].quality == "720P")  f[2] = n + 1;
    if (u[n].quality == "1080P") f[3] = n + 1;
  }

  fmt = getformat (f, fmt); fixformat (f, frame);
  n = argformat (fmt); fmt = pixformat (n); n = f[n] - 1;
  url = u[n].url; if (!url) throw ("!!!");

} catch (err) { console.log (err); busy = 0; }

  if (ss) id += "/" + ss + "/" + ep;
  if (no_fail (frame, id)) loadwindow (url, frame, tag, id, fmt);
}
////////////////////

frame_7.req_vtube = async (id, frame, fmt) =>
{
  var tag = "vtube"; id = getid (frame, id, 12);
  if (!id || is_busy (frame, tag + " (ID)", 0)) return;

  var src = "https://vtube.network", url = src + "/" + id + ".html";

if (stream_all (frame, 0)) fmt = ""; else try
{
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  var sub = pullstring (textData, "p,a,c,k,e,d", "<\/script>"); if (!sub) throw ("!!!");

  eval ("(sub=function(p,a,c,k,e,d" + sub); url = pullstring (sub, 'file:"', '"');

  if (!url.includes (".m3u8") || stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id);
}
////////////////////

frame_7.req_wootly = async (id, frame, fmt) =>
{
  var tag = "wootly"; id = getid (frame, id, 8);
  if (!id || is_busy (frame, tag + " (ID)", 2)) return;

  var c, h, s, t, u, url = "https://www.wootly.ch/?v=" + id;

try
{
  response = await kitty (cors_kraker + url);
  textData = await response.text();

  url = pullstring (textData, '<iframe src="', '"'); if (!url) throw ("!!!");
  h = { 'content-type': 'application/x-www-form-urlencoded', accept: "**" };

  response = await kitty (cors_kraker + url, { method: 'POST', headers: h, body: 'qdfx=1' });
  textData = await response.text();

  c = response.headers.get ("zz-set-cookie") || ""; c = pullstring (c, "", ";");
  t = pullstring (textData, 'tk="', '"'); u = pullstring (textData, 'vd="', '"');

  url = pullstring (url, "", "//") + "//" + pullstring (url, "//", "/");
  url += "/grabm?t=" + t + "&id=" + u; if (!t || !u) throw ("!!!");

  response = await kitty (cors_kraker + url, allow_cookie ("", c));
  textData = await response.text();

  url = textData; if (url.indexOf ("http")) throw ("!!!");

//  response = await kitty (cors_kraker + url, { method: 'HEAD', headers: { accept: '**' }});
//  if (s = response.headers.get ("zz-location")) url = s.replace (/:[^.]*.nebula./, "://orix.nebula.");

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame, id)) loadwindow (url, frame, tag, id);
}
////////////////////

frame_7.dig_thearchive = async (url, frame, fmt) =>
{
  var tag = "thearchive"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{ 
  response = await kitty (cors_local + url);
  textData = await response.text();

  url = pullstring (textData, 'data-ottera-id="', '"');

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) frame_7.req_thearchive (url, frame, fmt);
}
////////////////////

frame_7.dig_darkmatter = async (url, frame, fmt) =>
{
  var tag = "darkmatter"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  url = pullstring (textData, 'class="elementor-button-wrapper"', '>Watch Now<');
  url = pullstring (url, 'href="', '"'); url = url.substr (0, url.lastIndexOf ("/"));
  if (!url) throw ("!!!");

  response = await kitty (us_geo_bypass + url);
  textData = await response.text();

  if (!(url = pullstring (textData, '"sources":[{"uri":"', '"')))
  {
    if (!(url = pullstring (textData, '{"onnow":{"id":"', '"'))) throw ("!!!");
    url = "https://valencia-app-mds.xumo.com/v2/assets/asset/" + url + ".json";
    response = await kitty (cors_kraker + url);
    textData = await response.text();
    if (!(url = pullstring (textData, '"sources":[{"uri":"', '"'))) throw ("!!!");
  }

  if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame)) loadwindow (url, frame, tag, "?", fmt);
}
////////////////////

frame_7.dig_plextv = async (url, frame, fmt) =>
{
  var tag = "plextv"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{ 
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  url = pullstring (textData, '"key\\":\\"', '\\'); if (!url) throw ("!!!");

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) frame_7.req_plextv (url, frame, fmt);
}
////////////////////

frame_7.dig_ridomovies = async (url, frame, fmt) =>
{
  var tag = "ridomovies"; if (is_busy (frame, tag + " (DIG)", 2)) return;

try
{ 
  response = await kitty (cors_kraker + "!mock:1A|*" + url);
  textData = await response.text();

  if (url = pullstring (textData, 'data-video="', '"'))
  {
    busy = 0; frame_7.req_closeload (url, frame, fmt); return;
  }

  url = pullstring (textData, '"postid\\":\\"', '\\"'); if (!url) throw ("!!!");

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) frame_7.req_ridomovies (url, frame, fmt);
}
////////////////////

frame_7.dig_filmzie = async (url, frame, fmt) =>
{
  var tag = "filmzie"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  url = pullstring (textData, '"videos":[{"id":"', '"'); if (!url) throw ("!!!");

} catch (err) { console.log (err); busy = 0; }

  busy = -busy; if (no_fail (frame)) frame_7.req_filmzie (url, frame, fmt);
}
////////////////////

frame_7.dig_wconline = async (url, frame, fmt) =>
{
  var tag = "wconline"; if (is_busy (frame, tag + " (DIG)", 2)) return;
  var s, t, sub, f = [0,0,0,0], ua = cors_kraker + "**!mock:1A|*";

try
{ 
  response = await fetch (ua + url);
  textData = await response.text();

  if (url = "", s = pullstring (textData, "script>var", "document"))
  {
    t = pullstring (s, " ", " "); eval (s + "url=" + t); url = pullstring (url, 'src="', '"');
  }
  else if (s = pullstring (textData, "<iframe", ">")) url = pullstring (s, 'src="', '"');

  if (!url) throw ("!!!");

  response = await fetch (ua + url);
  textData = await response.text();

  s = pullstring (textData, 'getJSON("', '"'); if (!s) throw ("!!!");
  ua = cors_kraker + "**user-agent=abc|x-requested-with=XMLHttpRequest|*";

  response = await fetch (ua + "https://" + url.split ("/")[2] + s);
  jsonData = await response.json();

  t = ["", jsonData.enc, jsonData.hd, jsonData.fhd];
  if (t[1]) f[1] = 1; if (t[2]) f[2] = 1; if (t[3]) f[3] = 1;
  fmt = gotformat (f, fmt); fixformat (f, frame); url = t [fmt]; fmt = pixformat (fmt);

  url = cors_kraker + "~user-agent=abc|*" + jsonData.server + "/getvid?evid=" + url;

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame)) loadwindow (url, frame, tag, "?", fmt);
}
////////////////////

frame_7.dig_xvideos = async (url, frame, fmt) =>
{
  var tag = "xvideos"; if (is_busy (frame, tag + " (DIG)", 0)) return;

try
{
  response = await kitty (cors_bypass + url);
  textData = await response.text();

  if (url = pullstring (textData, "setVideoHLS('", "'")) if (stream_all (frame, 1)) fmt = 0; else
  {
    response = await kitty (url); textData = await response.text();
    [url,fmt] = crack_m3u8 (url, textData, frame, fmt);
  }
  else if (url = pullstring (textData, '"contentUrl": "', '"')) fmt = 0; else throw ("!!!");

} catch (err) { console.log (err); busy = 0; }

  if (no_fail (frame)) loadwindow (url, frame, tag, "?", fmt);
}
////////////////////
