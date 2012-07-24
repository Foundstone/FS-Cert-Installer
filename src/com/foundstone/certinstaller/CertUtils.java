package com.foundstone.certinstaller;

/*
 * Copyright (C) 2012 Foundstone
 * 
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

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
		return PreferenceManager.getDefaultSharedPreferences(context
				.getApplicationContext());
	}

}
