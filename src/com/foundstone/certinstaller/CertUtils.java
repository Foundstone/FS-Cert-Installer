package com.foundstone.certinstaller;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;

public class CertUtils {

    public static final String PREF_AUTO_LOAD = "pref_auto_load";
    public static final String PREF_PROXY_IP = "pref_proxy_ip";
    public static final String PREF_PROXY_PORT = "pref_proxy_port";

    public static final int INSTALL_CA_CODE = 2;
    public static final int INSTALL_SITE_CODE = 3;

    /**
     * @param context
     * @return the {@link SharedPreferences} for this app
     */
    public static SharedPreferences getSharedPreferences(Context context) {
        // Uses the Application Context
        return PreferenceManager.getDefaultSharedPreferences(context.getApplicationContext());
    }

}
