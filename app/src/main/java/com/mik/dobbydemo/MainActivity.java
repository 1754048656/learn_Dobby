package com.mik.dobbydemo;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import com.mik.dobbydemo.IO.NativeEngine;
import com.mik.dobbydemo.IO.passRoot.RootDetectUtil;
import com.mik.dobbydemo.utils.CLogUtils;

import java.io.File;
import java.io.FileInputStream;

public class MainActivity extends AppCompatActivity {

    static {
        try {

            CLogUtils.e("开始加载 Test so文件 ");
            System.loadLibrary("dobby");
            System.loadLibrary("mikDobby");
            System.loadLibrary("TestB");
            System.loadLibrary("IOHook");

        } catch (Throwable e) {
            CLogUtils.e("加载So出现异常 " + e.toString());
            e.printStackTrace();
        }
    }
    public Button button;

    public static native void TestB();
    public native void RegisterNativeTest(String str);
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        button=(Button)findViewById(R.id.button);
        String path= getExternalFilesDir(null).getPath();
        Log.e("mis","sdcard path:"+path);
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                CLogUtils.e("mik 文件是否存在 "+new File("/sbin/su").exists());

                NativeEngine.forbid("/sbin/su",true);

//                RootDetectUtil.anti();

                NativeEngine.redirectFile("/proc/cpuinfo", "/data/local/tmp/cpuinfo" );

                //开启IO重定向
                NativeEngine.enableIORedirect(getBaseContext());

                String res= FileHelper.ReadFileAll("/proc/cpuinfo");
                CLogUtils.e("mik cpuinfo: "+res);

                CLogUtils.e("mik 文件是否存在 "+new File("/sbin/su").exists());
            }
        });
    }
}