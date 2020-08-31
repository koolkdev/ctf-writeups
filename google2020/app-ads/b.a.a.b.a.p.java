package p034b.p035a.p036a.p039b.p040a;

import android.content.Intent;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.os.RemoteException;
import android.provider.CalendarContract.Events;
import android.util.Log;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import p034b.p041b.p042a.p043a.C0315a;
import p044c.p045a.p046a.p047a.C0316a;
import p044c.p045a.p046a.p047a.C0317b;

/* renamed from: b.a.a.b.a.p */
public class C0313p extends WebViewClient {

    /* renamed from: a */
    public static final Map<String, C0314q> f1092a;

    /* renamed from: b */
    public static Handler f1093b = new Handler(Looper.getMainLooper());

    static {
        HashMap hashMap = new HashMap();
        f1092a = hashMap;
        hashMap.put("log", C0301d.f1075a);
        f1092a.put("refresh", C0302e.f1076a);
        f1092a.put("init.mraid", C0309l.f1086a);
        f1092a.put("resize.mraid", C0306i.f1081a);
        f1092a.put("create-calendar-event.mraid", C0305h.f1080a);
        f1092a.put("play-video.mraid", C0299b.f1073a);
        f1092a.put("store-picture.mraid", C0298a.f1072a);
        f1092a.put("supports.mraid", C0300c.f1074a);
    }

    /* renamed from: a */
    public static /* synthetic */ Boolean m680a(WebResourceRequest webResourceRequest, C0312o oVar) {
        String str = "title";
        String queryParameter = webResourceRequest.getUrl().getQueryParameter(str);
        String queryParameter2 = webResourceRequest.getUrl().getQueryParameter("desc");
        String queryParameter3 = webResourceRequest.getUrl().getQueryParameter("loc");
        long parseLong = Long.parseLong(webResourceRequest.getUrl().getQueryParameter("start"));
        oVar.getContext().startActivity(new Intent("android.intent.action.INSERT").setData(Events.CONTENT_URI).putExtra("beginTime", parseLong).putExtra("endTime", Long.parseLong(webResourceRequest.getUrl().getQueryParameter("end"))).putExtra(str, queryParameter).putExtra("description", queryParameter2).putExtra("eventLocation", queryParameter3));
        m682a(oVar, "MRAID_CALLBACK('create-calendar-event', true)");
        return Boolean.valueOf(true);
    }

    /* renamed from: a */
    public static void m682a(C0312o oVar, String str) {
        f1093b.post(new C0310m(oVar, str));
    }

    /* renamed from: a */
    public static /* synthetic */ boolean m683a(C0312o oVar, WebResourceRequest webResourceRequest) {
        StringBuilder a = C0315a.m696a("JS: ");
        a.append(webResourceRequest.getUrl().getQueryParameter("msg"));
        Log.i("ExampleApp", a.toString());
        return true;
    }

    /* renamed from: b */
    public static /* synthetic */ Boolean m684b(WebResourceRequest webResourceRequest, C0312o oVar) {
        Intent intent = new Intent("android.intent.action.VIEW");
        intent.setDataAndType(Uri.parse(webResourceRequest.getUrl().getQueryParameter("uri")), "video/mp4");
        oVar.getContext().startActivity(intent);
        m682a(oVar, "MRAID_CALLBACK('play-video', true)");
        return Boolean.valueOf(true);
    }

    /* renamed from: d */
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

    /* renamed from: i */
    public static /* synthetic */ boolean m693i(C0312o oVar, WebResourceRequest webResourceRequest) {
        Boolean bool;
        try {
            bool = Log.i("ExampleApp", "MRAID: RESIZE is not supported");
        } catch (RemoteException | RuntimeException e) {
            Log.e("ExampleApp", "Something bad happened on the remote end", e);
            bool = null;
        }
        return bool.booleanValue();
    }

    public boolean shouldOverrideUrlLoading(WebView webView, WebResourceRequest webResourceRequest) {
        if (webResourceRequest.getUrl().getScheme().equals("ads")) {
            C0314q qVar = (C0314q) f1092a.get(webResourceRequest.getUrl().getHost());
            if (qVar != null) {
                return qVar.mo1375a((C0312o) webView, webResourceRequest);
            }
        }
        return super.shouldOverrideUrlLoading(webView, webResourceRequest);
    }
}
