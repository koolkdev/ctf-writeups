package p034b.p035a.p036a.p039b;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Base64;
import android.util.Log;
import dalvik.system.DexClassLoader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.CodeSigner;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import p044c.p045a.p046a.p047a.C0316a;

/* renamed from: b.a.a.b.b */
public class C0832b {

    /* renamed from: b */
    public static final CertPath f3211b = CertificateFactory.getInstance("X.509").generateCertPath(new ByteArrayInputStream(Base64.decode("MIIC6AYJKoZIhvcNAQcCoIIC2TCCAtUCAQExADALBgkqhkiG9w0BBwGgggK9MIICuTCCAaGgAwIBAgIEEVjZpzANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJVUzAeFw0yMDA1MTYwMTIzMjlaFw00NTA1MTAwMTIzMjlaMA0xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmaQMLr9fYBTElkq2Z7pPX9X1f5CYGdRVpuC3W/AIu9ec1WYXvJavFnSk5R9h8boKlqds6TQGnTu0NTbrXlMGN/XBy0qsqP7Kj2L7mv3k57YP35qc+gmSJZI3zqbYwpaTlP+cH6RLtKgOPnTw9WhZ/X+ohz3iv7b5Zt6NolPTATsDn0SiF5bWaOLQ/sEahDPoHIjWt9+Sy0p5z8QOHJY58iB0Fzls1BdgCFHtpAVf6VmoDEHvEsljJhq8/tqO62mhheHxaf93IJAD0Wyj0oUXDnBN+BiHw9bUqaQTuNchu7Fye3+WyR1SY1KA5vWzxkgR8zaNICsbZI7mvK5gS0AoWwIDAQABoyEwHzAdBgNVHQ4EFgQUAPOd0nsvVuw3TWifPOa75CxXO3cwDQYJKoZIhvcNAQELBQADggEBACCa/uAeLiB+d+L65jWJpHALJXfyoUqmO7KUfme15/4KbxzFvk1+b3pIcycaWgjA+UtLR94lt6mXSh07mfp2IY71TO96mUwrF8tFA/xSskpNrI3ogOdKV4PNn7GpkBM7xpI/XRp9vwloyJCfDgmVehq57n/hwTr9Ib1qqbRQSBO/qSNn9wxUmAdiirDjPM0FijAKuYBN70CLLEJZ+ry/arS+piqCJoU0US4w0jv6OCE8eVZj5rxdLkty4hcS3oFcXsgELQSKzVNl6uXor1rm3B5eN4/HouvHY45gMKvlZ3n7Gz1ZJ5sxSSBmpe7Ew8aOOcbjfC3gHbVU4BvpphAzeaQxAA==", 0)), "PKCS7");

    /* renamed from: a */
    public final ClassLoader f3212a;

    static {
        try {
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public C0832b(ClassLoader classLoader) {
        this.f3212a = classLoader;
    }

    /* renamed from: a */
    public static C0832b m2134a(Context context) {
        boolean z;
        String sb;
        AssetManager assets = context.getAssets();
        String str = "ads-impl.apk";
        File file = new File(context.getDir("ads", 0), str);
        String str2 = "ExampleApp";
        if (file.exists()) {
            try {
                JarFile jarFile = new JarFile(file, true);
                Enumeration entries = jarFile.entries();
                while (entries.hasMoreElements()) {
                    JarEntry jarEntry = (JarEntry) entries.nextElement();
                    if (jarEntry.getName().toUpperCase().endsWith(".DEX")) {
                        C0316a.m2137a(jarFile.getInputStream(jarEntry), new C0831a());
                        CodeSigner[] codeSigners = jarEntry.getCodeSigners();
                        if (codeSigners == null) {
                            StringBuilder sb2 = new StringBuilder();
                            sb2.append("Found an unsigned dex file: ");
                            sb2.append(jarEntry.getName());
                            sb = sb2.toString();
                        } else {
                            boolean z2 = false;
                            for (CodeSigner signerCertPath : codeSigners) {
                                if (f3211b.equals(signerCertPath.getSignerCertPath())) {
                                    z2 = true;
                                }
                            }
                            if (!z2) {
                                sb = "APK is not signed with valid cert";
                            }
                        }
                        Log.e(str2, sb);
                        z = false;
                        break;
                    }
                }
                z = true;
            } catch (IOException | RuntimeException e) {
                Log.e(str2, "Something fishy with the APK, best replace it", e);
            }
            if (z) {
                Log.i(str2, "Impl up to date, good to go!");
                return new C0832b(new DexClassLoader(file.toString(), context.getCodeCacheDir().toString(), null, Context.class.getClassLoader()));
            }
        }
        Log.i(str2, "Detected updated to impl, updating!!!");
        try {
            C0316a.m2137a(assets.open(str), new FileOutputStream(file));
            file.setReadable(true, false);
            file.setExecutable(true, false);
        } catch (IOException e2) {
            Log.e(str2, "Unable to copy jar file!!!", e2);
        }
        return new C0832b(new DexClassLoader(file.toString(), context.getCodeCacheDir().toString(), null, Context.class.getClassLoader()));
    }
}
