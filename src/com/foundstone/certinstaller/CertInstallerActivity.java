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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Proxy.Type;
import java.net.URI;
import java.net.URL;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;

import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.params.ConnManagerPNames;
import org.apache.http.conn.params.ConnPerRouteBean;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
import android.os.AsyncTask;
import android.os.Bundle;
import android.security.KeyChain;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.foundstone.certinstaller.EasyX509TrustManager.OnCertsRecievedListener;

public class CertInstallerActivity extends Activity implements OnClickListener,
		OnCertsRecievedListener, TextWatcher, OnSharedPreferenceChangeListener {

	// Use for debug
	private static final String TAG = CertInstallerActivity.class
			.getSimpleName();

	private String mResult = "";
	private Boolean mCaCertInstalled = false;
	private Boolean mSiteCertInstalled = false;

	private TextView mCaCertInstalledText;
	private TextView mSiteCertInstalledText;
	private TextView mFullCertChainErrorText;
	private X509Certificate caCert = null;
	private X509Certificate siteCert = null;
	private ProgressDialog pd;

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		Log.d(TAG, "FS Cert Installer starting...");

		setContentView(R.layout.start);

		final SharedPreferences sharedPrefs = CertUtils
				.getSharedPreferences(this);

		Log.d(TAG, Boolean.toString(sharedPrefs.getBoolean(
				CertUtils.PREF_AUTO_LOAD, false)));
		if (sharedPrefs.getBoolean(CertUtils.PREF_AUTO_LOAD, false)) {
			((EditText) findViewById(R.id.ip_input_text)).setText(sharedPrefs
					.getString(CertUtils.PREF_PROXY_IP, ""));
			((EditText) findViewById(R.id.port_input_text)).setText(sharedPrefs
					.getString(CertUtils.PREF_PROXY_PORT, ""));
		}

		// Do this so anytime they change any setting we reset the certs
		((EditText) findViewById(R.id.url_input_text))
				.addTextChangedListener(this);
		((EditText) findViewById(R.id.ip_input_text))
				.addTextChangedListener(this);
		((EditText) findViewById(R.id.port_input_text))
				.addTextChangedListener(this);

		mCaCertInstalledText = (TextView) findViewById(R.id.ca_error_text);
		mSiteCertInstalledText = (TextView) findViewById(R.id.site_error_text);
		mFullCertChainErrorText = (TextView) findViewById(R.id.full_error_text);

		findViewById(R.id.test_cert_chain_button).setOnClickListener(this);
		findViewById(R.id.install_ca_button).setOnClickListener(this);
		findViewById(R.id.install_site_cert_button).setOnClickListener(this);

	}

	@Override
	protected void onResume() {
		super.onResume();
		// Attach when active
		CertUtils.getSharedPreferences(this)
				.registerOnSharedPreferenceChangeListener(this);
	}

	@Override
	protected void onPause() {
		super.onPause();
		// Detach when not active
		CertUtils.getSharedPreferences(this)
				.unregisterOnSharedPreferenceChangeListener(this);
	}

	/**
	 * Tests the certificate chain by making a connection with or without the
	 * proxy to the specified URL
	 * 
	 * @param urlString
	 * @param proxyIP
	 * @param proxyPort
	 */
	private void testCertChain(final String urlString, final String proxyIP,
			final String proxyPort) {

		mCaCertInstalled = false;
		mSiteCertInstalled = false;

		if (TextUtils.isEmpty(urlString)) {
			Toast.makeText(getApplicationContext(), "URL is not set",
					Toast.LENGTH_SHORT).show();
			Log.d(TAG, "URL is not set");
			return;
		}
		pd = ProgressDialog.show(CertInstallerActivity.this,
				"Testing the cert chain", "", true, false, null);

		new AsyncTask<Void, Void, Void>() {
			@Override
			protected Void doInBackground(Void... params) {

				Log.d(TAG, "[+] Starting HTTPS request...");

				HttpsURLConnection urlConnection = null;

				try {
					Log.d(TAG, "[+] Set URL...");
					URL url = new URL("https://" + urlString);

					Log.d(TAG, "[+] Open Connection...");

					// The user could have ProxyDroid running
					if (!TextUtils.isEmpty(proxyIP)
							&& !TextUtils.isEmpty(proxyPort)) {
						Log.d(TAG, "[+] Using proxy " + proxyIP + ":"
								+ proxyPort);
						Proxy proxy = new Proxy(Type.HTTP,
								new InetSocketAddress(proxyIP,
										Integer.parseInt(proxyPort)));
						urlConnection = (HttpsURLConnection) url
								.openConnection(proxy);
					} else {
						urlConnection = (HttpsURLConnection) url
								.openConnection();
					}
					urlConnection.setReadTimeout(15000);

					Log.d(TAG, "[+] Get the input stream...");
					InputStream in = urlConnection.getInputStream();
					Log.d(TAG,
							"[+] Create a buffered reader to read the response...");
					BufferedReader reader = new BufferedReader(
							new InputStreamReader(in));

					final StringBuilder builder = new StringBuilder();

					String line = null;
					Log.d(TAG, "[+] Read all of the return....");
					while ((line = reader.readLine()) != null) {
						builder.append(line);
					}

					mResult = builder.toString();

					Log.d(TAG, mResult);

					// If everything passed we set these both to true
					mCaCertInstalled = true;
					mSiteCertInstalled = true;

					// Catch when the CA doesn't exist
					// Error: javax.net.ssl.SSLHandshakeException:
					// java.security.cert.CertPathValidatorException: Trust
					// anchor for certification path not found
				} catch (SSLHandshakeException e) {

					e.printStackTrace();

					// Catch when the hostname does not verify
					// Line 224ish
					// http://source-android.frandroid.com/libcore/luni/src/main/java/libcore/net/http/HttpConnection.java
					// http://docs.oracle.com/javase/1.4.2/docs/api/javax/net/ssl/HostnameVerifier.html#method_detail
				} catch (IOException e) {

					// Found the CA cert installed but not the site cert
					mCaCertInstalled = true;
					e.printStackTrace();
				} catch (Exception e) {
					Log.d(TAG, "[-] Some other exception: " + e.getMessage());
					e.printStackTrace();
				}

				return null;
			}

			@Override
			protected void onPostExecute(Void result) {

				pd.dismiss();
				if (mCaCertInstalled && !mSiteCertInstalled) {
					Log.d(TAG, Boolean.toString(mCaCertInstalled));
					Toast.makeText(getApplicationContext(),
							"Found the CA cert installed", Toast.LENGTH_SHORT)
							.show();
					setCaTextInstalled();
					setSiteTextNotInstalled();
					setFullTextNotInstalled();
				} else if (mCaCertInstalled && mSiteCertInstalled) {
					Toast.makeText(getApplicationContext(),
							"Found the CA and Site certs installed",
							Toast.LENGTH_SHORT).show();
					setCaTextInstalled();
					setSiteTextInstalled();
					setFullTextInstalled();
				} else {
					Toast.makeText(getApplicationContext(),
							"No Certificates were found installed",
							Toast.LENGTH_SHORT).show();
					setCaTextNotInstalled();
					setSiteTextNotInstalled();
					setFullTextNotInstalled();
				}
				super.onPostExecute(result);

			}

		}.execute();

	}

	/**
	 * Install the CA certificate. First check if we have the certificate, if
	 * not open a connection and grab the certificates. Once the certificates
	 * are found launch intent with an X509Cert to be installed to the KeyChain.
	 * 
	 * @param urlString
	 * @param proxyIP
	 * @param proxyPort
	 */
	private void installCACert(String urlString, String proxyIP,
			String proxyPort) {
		if (TextUtils.isEmpty(urlString)) {
			Toast.makeText(getApplicationContext(), "URL is not set",
					Toast.LENGTH_SHORT).show();
			Log.d(TAG, "URL is not set");
			return;
		} else if (TextUtils.isEmpty(proxyIP)) {
			Toast.makeText(getApplicationContext(), "Port is not set",
					Toast.LENGTH_SHORT).show();
			Log.d(TAG, "Port is not set");
			return;
		}

		if (caCert == null) {
			pd = ProgressDialog.show(CertInstallerActivity.this,
					"Getting the CA certificate", "", true, false, null);

			grabCerts(urlString, proxyIP, proxyPort);
			try {
				while (caCert == null) {
					Thread.sleep(10);
				}
			} catch (InterruptedException e1) {
				e1.printStackTrace();
			}

			pd.dismiss();
		}

		try {
			installCert(caCert, CertUtils.INSTALL_CA_CODE);
		} catch (Exception e) {
			setCaTextNotInstalled();
			e.printStackTrace();
		}

	}

	/**
	 * Install the site certificate. First check if we have the certificate, if
	 * not open a connection and grab the certificates. Once the certificates
	 * are found launch intent with an X509Cert to be installed to the KeyChain.
	 * 
	 * @param urlString
	 * @param proxyIP
	 * @param proxyPort
	 */
	private void installSiteCert(String urlString, String proxyIP,
			String proxyPort) {
		if (TextUtils.isEmpty(urlString)) {
			Toast.makeText(getApplicationContext(), "URL is not set",
					Toast.LENGTH_SHORT).show();
			Log.d(TAG, "URL was not set");
			return;
		} else if (TextUtils.isEmpty(proxyIP)) {
			Toast.makeText(getApplicationContext(), "Port is not set",
					Toast.LENGTH_SHORT).show();
			Log.d(TAG, "Port is not set");
			return;
		}
		if (siteCert == null) {
			pd = ProgressDialog.show(CertInstallerActivity.this,
					"Getting the Site certificate", "", true, false, null);

			grabCerts(urlString, proxyIP, proxyPort);
			pd.dismiss();
		}
		try {
			installCert(siteCert, CertUtils.INSTALL_SITE_CODE);
		} catch (Exception e) {
			setSiteTextNotInstalled();
			e.printStackTrace();
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.view.View.OnClickListener#onClick(android.view.View)
	 */
	public void onClick(View v) {
		switch (v.getId()) {
		case R.id.test_cert_chain_button:
			testCertChain(getURL(), getIP(), getPort());
			break;
		case R.id.install_ca_button:
			installCACert(getURL(), getIP(), getPort());
			break;
		case R.id.install_site_cert_button:
			installSiteCert(getURL(), getIP(), getPort());
			break;
		default:
			break;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.foundstone.certinstaller.EasyX509TrustManager.OnCertsRecievedListener
	 * #OnCertsRecieved(java.security.cert.X509Certificate[])
	 */
	public void OnCertsRecieved(X509Certificate[] certificates) {
		for (X509Certificate cert : certificates) {
			// Non-CA's get Int.MAX
			if (cert.getBasicConstraints() == Integer.MAX_VALUE) {
				siteCert = cert;
			} else {
				caCert = cert;
			}
		}
	}

	/**
	 * Build a connection using the custom Trust Manager and Socket Factory to
	 * grab the certificates.
	 * 
	 * @param urlString
	 * @param proxyIP
	 * @param proxyPort
	 */
	public void grabCerts(final String urlString, final String proxyIP,
			final String proxyPort) {
		new AsyncTask<Void, Void, Void>() {
			@Override
			protected Void doInBackground(Void... params) {

				SchemeRegistry schemeRegistry = new SchemeRegistry();
				schemeRegistry.register(new Scheme("http", PlainSocketFactory
						.getSocketFactory(), 80));
				schemeRegistry.register(new Scheme("https",
						new EasySSLSocketFactory(CertInstallerActivity.this),
						443));

				HttpParams httpParams = new BasicHttpParams();
				httpParams.setParameter(
						ConnManagerPNames.MAX_TOTAL_CONNECTIONS, 30);
				httpParams.setParameter(
						ConnManagerPNames.MAX_CONNECTIONS_PER_ROUTE,
						new ConnPerRouteBean(30));
				httpParams.setParameter(HttpProtocolParams.USE_EXPECT_CONTINUE,
						false);
				Log.d(TAG, proxyIP);
				Log.d(TAG, proxyPort);
				httpParams.setParameter(ConnRoutePNames.DEFAULT_PROXY,
						new HttpHost(proxyIP, Integer.parseInt(proxyPort)));
				HttpProtocolParams.setVersion(httpParams, HttpVersion.HTTP_1_1);

				ClientConnectionManager cm = new ThreadSafeClientConnManager(
						httpParams, schemeRegistry);

				DefaultHttpClient defaultClient = new DefaultHttpClient(cm,
						httpParams);
				HttpGet httpget = new HttpGet();
				try {
					httpget.setURI(new URI("https://" + urlString));
					Log.d(TAG, urlString);

					HttpResponse httpResponse = defaultClient.execute(httpget);
					InputStream in = httpResponse.getEntity().getContent();
					// Once this connection is made the certs are grabbed
					BufferedReader reader = new BufferedReader(
							new InputStreamReader(in));

					in.close();
				} catch (Exception e) {
					e.printStackTrace();
				}

				return null;
			}

		}.execute();
	}

	/**
	 * Install the X509Certificate using the KeyChain intent and specifying a
	 * certificate. The return code is used here to know when type of cert was
	 * installed.
	 * 
	 * @param cert
	 * @param code
	 * @throws Exception
	 */
	private void installCert(X509Certificate cert, Integer code)
			throws Exception {

		byte[] keystore = cert.getEncoded();
		Intent installIntent = KeyChain.createInstallIntent();
		installIntent.putExtra(KeyChain.EXTRA_CERTIFICATE, keystore);
		startActivityForResult(installIntent, code);
	}

	/**
	 * @return the URL set
	 */
	private String getURL() {
		return ((EditText) findViewById(R.id.url_input_text)).getText()
				.toString();
	}

	/**
	 * @return the IP set
	 */
	private String getIP() {
		return ((EditText) findViewById(R.id.ip_input_text)).getText()
				.toString();
	}

	/**
	 * @return the Port set
	 */
	private String getPort() {
		return ((EditText) findViewById(R.id.port_input_text)).getText()
				.toString();
	}

	/**
	 * Set the CA Certificate text to No and red.
	 */
	private void setCaTextNotInstalled() {
		mCaCertInstalledText.setTextColor(getResources().getColor(
				android.R.color.holo_red_light));
		mCaCertInstalledText.setText("No");
	}

	/**
	 * Set the site certificate text to No and red.
	 */
	private void setSiteTextNotInstalled() {
		mSiteCertInstalledText.setTextColor(getResources().getColor(
				android.R.color.holo_red_light));
		mSiteCertInstalledText.setText("No");
	}

	/**
	 * Set the CA certificate text to Yes and green.
	 */
	private void setCaTextInstalled() {
		mCaCertInstalledText.setTextColor(getResources().getColor(
				android.R.color.holo_green_light));
		mCaCertInstalledText.setText("Yes");
	}

	/**
	 * Set the site certificate text to Yes and green.
	 */
	private void setSiteTextInstalled() {
		mSiteCertInstalledText.setTextColor(getResources().getColor(
				android.R.color.holo_green_light));
		mSiteCertInstalledText.setText("Yes");
	}

	/**
	 * Set the full chain text to Yes and green.
	 */
	private void setFullTextInstalled() {
		mFullCertChainErrorText.setTextColor(getResources().getColor(
				android.R.color.holo_green_light));
		mFullCertChainErrorText.setText("Yes");
	}

	/**
	 * Set the full chain text to No and red.
	 */
	private void setFullTextNotInstalled() {
		mFullCertChainErrorText.setTextColor(getResources().getColor(
				android.R.color.holo_red_light));
		mFullCertChainErrorText.setText("No");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.text.TextWatcher#afterTextChanged(android.text.Editable)
	 */
	public void afterTextChanged(Editable s) {
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.text.TextWatcher#beforeTextChanged(java.lang.CharSequence,
	 * int, int, int)
	 */
	public void beforeTextChanged(CharSequence s, int start, int count,
			int after) {
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.text.TextWatcher#onTextChanged(java.lang.CharSequence, int,
	 * int, int)
	 */
	public void onTextChanged(CharSequence s, int start, int before, int count) {
		caCert = null;
		siteCert = null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.app.Activity#onActivityResult(int, int,
	 * android.content.Intent)
	 */
	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {

		switch (requestCode) {
		case 2:
			setCaTextInstalled();
			break;
		case 3:
			setSiteTextInstalled();
			break;
		default:
			break;
		}

		super.onActivityResult(requestCode, resultCode, data);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.app.Activity#onCreateOptionsMenu(android.view.Menu)
	 */
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		MenuInflater inflater = getMenuInflater();
		inflater.inflate(R.layout.menu, menu);
		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.app.Activity#onOptionsItemSelected(android.view.MenuItem)
	 */
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle item selection
		switch (item.getItemId()) {
		case R.id.settings:
			Intent i = new Intent(this, PrefsActivity.class);
			startActivity(i);
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see android.content.SharedPreferences.OnSharedPreferenceChangeListener#
	 * onSharedPreferenceChanged(android.content.SharedPreferences,
	 * java.lang.String)
	 */
	public void onSharedPreferenceChanged(SharedPreferences sharedPreferences,
			String key) {
		if (key.equals(CertUtils.PREF_AUTO_LOAD)
				&& sharedPreferences
						.getBoolean(CertUtils.PREF_AUTO_LOAD, false)) {
			((EditText) findViewById(R.id.ip_input_text))
					.setText(sharedPreferences.getString(
							CertUtils.PREF_PROXY_IP, ""));
			((EditText) findViewById(R.id.port_input_text))
					.setText(sharedPreferences.getString(
							CertUtils.PREF_PROXY_PORT, ""));
		}

	}
}
