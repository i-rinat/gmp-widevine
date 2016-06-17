Enable Widevine on Firefox 47
=============================

Firefox 47 (and probably later versions) have own adapter for Chrome CDMs.
But it is not enabled at compilation time. Therefore to get Widevine
working you still need to build own version, but don't need to patch sources
anymore.

First, create a working directory, go there, and download Firefox 47 source code:
```
wget https://ftp.mozilla.org/pub/firefox/releases/47.0/source/firefox-47.0.source.tar.xz
```

Then, extract it:
```
tar xaf firefox-47.0.source.tar.xz
cd firefox-47.0
```

Create a `.mozconfig` file:

```
echo "ac_add_options --enable-eme=widevine" >> .mozconfig
```

(`.mozconfig` may also contain other settings if you need them. Avoid
disabling jemalloc, since libc6 allocator sometimes opens a file, which
interferes with GMP sandbox.)

Build:
```
./mach build
```

After build completion, make a package, archive with all binaries required to
run Firefox:
```
./mach package
```

Directory where package is created, could differ from machine to machine.
In my case, it's
`./obj-x86_64-unknown-linux-gnu/dist/firefox-47.0.en-US.linux-x86_64.tar.bz2`)

The following assumes, you have a way to launch built Firefox. You can either
unpack a recently created package somewhere, or just launch it from build
directory (`./obj-x86_64-unknown-linux-gnu/dist/bin/`).

Then you need to determine, where your profile directory is. Launch Firefox,
open `about:support`. Find there "Profile Directory" line in the
"Application Basics" table, press "Open Directory" button. In that directory,
create subdirectory named `gmp-widevinecdm`. Go there and make subdirectory
named `1.4.8.885`. Copy there `libwidevinecdm.so` file from Chrome
(you'll find it in `/opt/google/chrome/libwidevinecdm.so` if Chrome is
installed). Also create a text file named `manifest.json` with the following
content:

```json
{
  "manifest_version": 2,
  "update_url": "https://clients2.google.com/service/update2/crx",
  "name": "WidevineCdm",
  "description": "Widevine Content Decryption Module",
  "offline_enabled": false,
  "version": "1.4.8.885",
  "minimum_chrome_version": "43.0.2340.0",
  "x-cdm-module-versions": "4",
  "x-cdm-interface-versions": "8",
  "x-cdm-host-versions": "8",
  "x-cdm-codecs": "vp8,vp9.0,vorbis,avc1"
}
```

Assuming your profile is located in `$PROFILE`, you should have:
```
$PROFILE/gmp-widevinecdm/1.4.8.885/libwidevinecdm.so
$PROFILE/gmp-widevinecdm/1.4.8.885/manifest.json
```

Then swith to Firefox again, open `about:config` page. Create string
parameter (right mouse button, New, String) with name
`media.gmp-widevinecdm.version` and value `1.4.8.885`.

That it. Go to http://shaka-player-demo.appspot.com/demo/ and try
some Widevine protected video.
