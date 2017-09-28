package com.forthe.sniffer;

import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import java.io.DataOutputStream;
import java.io.File;
import java.io.InputStream;

public class MainActivity13 extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        //upgradeRootPermission(getPackageCodePath());
        // Example of a call to a native method
        //TextView tv = (TextView) findViewById(R.id.sample_text);
        new Thread(){
            @Override
            public void run() {
                File f = new File(Environment.getExternalStorageDirectory().getAbsolutePath(),"sniffer");
                if(!f.exists()){
                    f.mkdirs();
                }else if(f.isFile()){
                    f.delete();
                    f.mkdirs();
                }
                runSniffer(f.getPath());
            }
        }.start();
    }

    public static boolean runSniffer(String path) {
        Log.e("sniffer path", path);
        Process process = null;
        DataOutputStream os = null;
        try {
            String cmd= path + "/sniffer "+path;
            process = Runtime.getRuntime().exec("su"); //切换到root帐号
            os = new DataOutputStream(process.getOutputStream());
            os.writeBytes(cmd + "\n");
            os.flush();
            process.waitFor();
        } catch (Exception e) {
            return false;
        } finally {
            try {
                if (os != null) {
                    os.close();
                }
                process.destroy();
            } catch (Exception e) {
            }
        }
        return true;
    }


    public native void startSniffer(String path);

    /**
     * 应用程序运行命令获取 Root权限，设备必须已破解(获得ROOT权限)
     *
     * @return 应用程序是/否获取Root权限
     */
    public static boolean upgradeRootPermission(String pkgCodePath) {
        Log.e("pkgCodePath", pkgCodePath);
        Process process = null;
        DataOutputStream os = null;
        try {
            String cmd="chmod 7777 " + pkgCodePath;
            process = Runtime.getRuntime().exec("su"); //切换到root帐号
            os = new DataOutputStream(process.getOutputStream());
            os.writeBytes(cmd + "\n");
            os.writeBytes("exit\n");
            os.flush();

//            InputStream is = process.getInputStream();
            process.waitFor();
        } catch (Exception e) {
            return false;
        } finally {
            try {
                if (os != null) {
                    os.close();
                }
                process.destroy();
            } catch (Exception e) {
            }
        }
        return true;
    }

}
