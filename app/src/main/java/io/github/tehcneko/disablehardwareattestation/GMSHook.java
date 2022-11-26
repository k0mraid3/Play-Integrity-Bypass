package io.github.tehcneko.disablehardwareattestation;

import android.annotation.SuppressLint;
import android.os.Build;
import android.util.Log;

import java.lang.reflect.Field;
import java.security.KeyStore;
import java.util.Arrays;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

@SuppressLint("DiscouragedPrivateApi")
@SuppressWarnings("ConstantConditions")
public class GMSHook implements IXposedHookLoadPackage {

    private static final String TAG = "GMSHook";
    private static final String PROVIDER_NAME = "AndroidKeyStore";
    private static final String ANGER_FINGERPRINT = "google/angler/angler:6.0/MDB08L/2343525:user/release-keys";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) {
        if ("com.google.android.gms".equals(loadPackageParam.packageName)) {
            if (!"com.google.android.gms.unstable".equals(loadPackageParam.processName)) {
                Log.d(TAG, "not droid guard process: " + loadPackageParam.processName);
                return;
            }
            try {
                Field model = Build.class.getDeclaredField("MODEL");
                model.setAccessible(true);
                model.set(null, Build.MODEL + " ");
                Log.d(TAG, "model changed");
            } catch (Throwable t) {
                XposedBridge.log("model change failed: " + Log.getStackTraceString(t));
            }
            try {
                Field fingerprint = Build.class.getDeclaredField("FINGERPRINT");
                fingerprint.setAccessible(true);
                fingerprint.set(null, ANGER_FINGERPRINT);
                Log.d(TAG, "fingerprint changed");
            } catch (Throwable t) {
                XposedBridge.log("fingerprint change failed: " + Log.getStackTraceString(t));
            }
            try {
                KeyStore keyStore = KeyStore.getInstance(PROVIDER_NAME);
                Field keyStoreSpi = keyStore.getClass().getDeclaredField("keyStoreSpi");
                keyStoreSpi.setAccessible(true);
                XposedHelpers.findAndHookMethod(keyStoreSpi.get(keyStore).getClass(), "engineGetCertificateChain", String.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        if (isCallerDroidGuard()) {
                            param.setThrowable(new UnsupportedOperationException());
                        }
                    }
                });
                Log.d(TAG, "keystore hooked");
            } catch (Throwable t) {
                XposedBridge.log("keystore hook failed: " + Log.getStackTraceString(t));
            }
        }
    }

    private static boolean isCallerDroidGuard() {
        return Arrays.stream(Thread.currentThread().getStackTrace()).anyMatch(stackTraceElement -> stackTraceElement.getClassName().toLowerCase().contains("droidguard"));
    }

}
