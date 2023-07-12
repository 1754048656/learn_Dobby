package com.mik.dobbydemo;

import android.app.Application;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;

import com.mik.dobbydemo.IO.NativeEngine;
import com.mik.dobbydemo.utils.AppUtils;
import com.mik.dobbydemo.utils.CLogUtils;

import java.io.File;
import java.util.Objects;

/**
 * @author Zhenxi on 2020-08-31
 */
public class App extends Application {
    private static Context ApplicationContext;



    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);

        //TestIO(base);

    }

    public static void TestIO(Context base) {
        try {

            PackageManager packageManager = base.getPackageManager();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                packageManager.clearInstantAppCookie();
            }

//            CLogUtils.e(new File(Objects.requireNonNull(
//                    AppUtils.getAPKPath(base))).getCanonicalPath());

            NativeEngine.redirectFile(
                    new File(Objects.requireNonNull(
                            AppUtils.getAPKPath(base))).getCanonicalPath(),
                    "/sdcard/base.apk");
        } catch (Throwable e) {
            CLogUtils.e("btIOAPK 出异常 "+e.getMessage());
            e.printStackTrace();
        }
        NativeEngine.enableIORedirect(base);

    }


    @Override
    public void onCreate() {
        super.onCreate();
        ApplicationContext=getBaseContext();
    }

    public static Context getAppContext(){
        return ApplicationContext;
    }
}
