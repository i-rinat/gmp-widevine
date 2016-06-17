gmp-widevine
============

Adapt Widevine
[CDM](https://w3c.github.io/encrypted-media/#definitions) from Google
Chrome to work in Firefox as a
[GMP](https://wiki.mozilla.org/GeckoMediaPlugins) plugin.

Mainline version of Firefox doesn't have necessary bits of EME
implemented yet, but Firefox Nightly already have them working.
(January 2016). I used source snapshot 29258f59e545 from
mozilla-central with [firefox.patch](firefox.patch) applied.  It
remained unknown to me where Firefox looks up for GMP plugins, so
`MOZ_GMP_PATH` environment variable was used instead.  Note, it should
point to directory path which ends with `.../gmp-widevine/1`. So one
should create directory `gmp-widevine` somewhere, then directory `1`
(a number, one) inside it, then copy
[data/widevine.info](data/widevine.info) and generated
`libwidevine.so` there.
[Here](https://wiki.mozilla.org/GeckoMediaPlugins#How_Gecko_Loads_a_GMP)
one can find original description of how that method works. Maybe one
will have to use LD_PRELOAD to preload
`/opt/google/chrome/libwidevinecdm.so`, since adapter can't do it
itself due to sandboxing.

To test, go to [https://shaka-player-demo.appspot.com] and select a
stream with "Widevine" or "multi-DRM". You could also try Netflix or
Google Play, but you have to change User-Agent to Chrome.

Firefox 47 (and later)
----------------------

There is less invasive way: see [how-to-enable-on-firefox-47.md](how-to-enable-on-firefox-47.md).
