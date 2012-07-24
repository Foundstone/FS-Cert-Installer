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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Trust manager to go with the SSL socket factory to accept all certificates.
 */
public class EasyX509TrustManager implements X509TrustManager {

	private X509TrustManager standardTrustManager = null;

	private final OnCertsRecievedListener mListener;

	/**
	 * Constructor for EasyX509TrustManager.
	 */
	public EasyX509TrustManager(KeyStore keystore,
			OnCertsRecievedListener listener) throws NoSuchAlgorithmException,
			KeyStoreException {
		super();
		TrustManagerFactory factory = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		factory.init(keystore);
		TrustManager[] trustmanagers = factory.getTrustManagers();
		if (trustmanagers.length == 0) {
			throw new NoSuchAlgorithmException("no trust manager found");
		}
		this.standardTrustManager = (X509TrustManager) trustmanagers[0];
		mListener = listener;
	}

	/**
	 * @see javax.net.ssl.X509TrustManager#checkClientTrusted(X509Certificate[],
	 *      String authType)
	 */
	public void checkClientTrusted(X509Certificate[] certificates,
			String authType) throws CertificateException {
		standardTrustManager.checkClientTrusted(certificates, authType);
	}

	/**
	 * @see javax.net.ssl.X509TrustManager#checkServerTrusted(X509Certificate[],
	 *      String authType)
	 */
	public void checkServerTrusted(X509Certificate[] certificates,
			String authType) throws CertificateException {
		if ((certificates != null) && (certificates.length == 1)) {
			certificates[0].checkValidity();
		} else {
			if (null != mListener)
				mListener.OnCertsRecieved(certificates);
			standardTrustManager.checkServerTrusted(certificates, authType);
		}
	}

	/**
	 * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
	 */
	public X509Certificate[] getAcceptedIssuers() {
		return this.standardTrustManager.getAcceptedIssuers();
	}

	/**
	 * This interface is triggered when certificates need to be checked
	 * 
	 * @author Paul
	 * 
	 */
	public interface OnCertsRecievedListener {

		/**
		 * Call back for certs to be added
		 * 
		 * @param certificates
		 *            - the certificates attached to a call
		 */
		public void OnCertsRecieved(X509Certificate[] certificates);

	}

}
