package com.mik.dobbydemo.utils;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import com.mik.dobbydemo.App;

import java.io.File;

/**
 * @author Zhenxi on 2021/5/30
 */
public class AppUtils {

    public static String getAPKPath(Context context) {

        PackageManager pm = context.getPackageManager();
        PackageInfo packageInfo = null;
        try {
            packageInfo = pm.getPackageInfo(context.getPackageName(), 0);
        } catch (Throwable e) {
            CLogUtils.e("getAPKPath error "+e.getMessage());
            e.printStackTrace();
        }

        if (packageInfo != null) {
            return packageInfo.applicationInfo.publicSourceDir;
        }
        return null;
    }

    public static File getAPKFile(Context context) {

        PackageManager pm = context.getPackageManager();
        PackageInfo packageInfo = null;
        try {
            packageInfo = pm.getPackageInfo(context.getPackageName(), 0);
        } catch (Throwable e) {
            CLogUtils.e("getAPKPath error "+e.getMessage());
            e.printStackTrace();
        }

        if (packageInfo != null) {
            return new File(packageInfo.applicationInfo.publicSourceDir);
        }
        CLogUtils.e("getAPKFile 文件Null ",new Exception(""));
        return null;
    }



    public static String getAPKPath() {

        PackageManager pm = App.getAppContext().getPackageManager();
        PackageInfo packageInfo = null;
        try {
            packageInfo = pm.getPackageInfo(App.getAppContext().getPackageName(), 0);
        } catch (Throwable e) {
            CLogUtils.e("getAPKPath error "+e.getMessage());
            e.printStackTrace();
        }

        if (packageInfo != null) {
            return packageInfo.applicationInfo.publicSourceDir;
        }
        return null;
    }

    public static File getAPKFile() {

        PackageManager pm = App.getAppContext().getPackageManager();
        PackageInfo packageInfo = null;
        try {
            packageInfo = pm.getPackageInfo(App.getAppContext().getPackageName(), 0);
        } catch (Throwable e) {
            CLogUtils.e("getAPKPath error "+e.getMessage());
            e.printStackTrace();
        }

        if (packageInfo != null) {
            return new File(packageInfo.applicationInfo.publicSourceDir);
        }
        return null;
    }

}
