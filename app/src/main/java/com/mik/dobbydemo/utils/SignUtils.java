package com.mik.dobbydemo.utils;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.MessageDigest;


public class SignUtils {

    public static void getSign(Context context){
        try {
            PackageInfo packageInfo = context.getPackageManager()
                    .getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);

            /******* 通过返回的包信息获得签名数组 *******/
            Signature[] signatures = packageInfo.signatures;

            byte[] bytes = signatures[0].toByteArray();

            MessageDigest localMessageDigest = MessageDigest.getInstance("MD5");
            localMessageDigest.update(bytes);
            byte[] digest = localMessageDigest.digest();

            CLogUtils.e(bytes2hex01(digest));
            CLogUtils.e(packageInfo.packageName);
            CLogUtils.e(getPmsName(context));

        } catch (Throwable e) {
            e.printStackTrace();
        }

    }

    public static void getSign(Signature[] signatures){
        if(signatures==null){
            CLogUtils.e("IO以后 getSign ==null");
            return;
        }
        try {
            byte[] bytes = signatures[0].toByteArray();

            MessageDigest localMessageDigest = MessageDigest.getInstance("MD5");
            localMessageDigest.update(bytes);
            byte[] digest = localMessageDigest.digest();

            CLogUtils.e("IO以后 "+bytes2hex01(digest));
        } catch (Throwable e) {
            CLogUtils.e("IO以后签名 error "+e.getMessage());
            e.printStackTrace();
        }
    }


    /**
     * 方式一
     *
     * @param bytes
     * @return
     */
    public static String bytes2hex01(byte[] bytes)
    {
        /**
         * 第一个参数的解释，记得一定要设置为1
         *  signum of the number (-1 for negative, 0 for zero, 1 for positive).
         */
        BigInteger bigInteger = new BigInteger(1, bytes);
        return bigInteger.toString(16);
    }


    public static String getPmsName(Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            Field mPmField = pm.getClass().getDeclaredField("mPM");
            mPmField.setAccessible(true);
            return mPmField.get(pm).getClass().getName();

        } catch (Throwable e) {
            CLogUtils.e("getPmsName error " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

}
