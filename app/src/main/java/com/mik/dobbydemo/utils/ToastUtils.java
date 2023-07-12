package com.mik.dobbydemo.utils;

import android.content.Context;
import android.widget.Toast;


public class ToastUtils {

    public static void makeToast(final String text, final Context context) {


        try {
            ThreadUtils.handler.post(new Runnable() {
                @Override
                public void run() {
                    Toast toast = Toast.makeText(context, text, Toast.LENGTH_LONG);
                    toast.show();
                }
            });
        } catch (Exception e) {
        }
    }
}
