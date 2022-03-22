/*
 * Copyright (c) 2011-2022 Contributors to the Eclipse Foundation
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */

package io.vertx.core.net;

import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;

import io.netty.handler.ssl.OpenSslServerContext;
import io.netty.handler.ssl.OpenSslServerSessionContext;
import io.netty.handler.ssl.SslContext;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.impl.VertxInternal;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.impl.SSLHelper;
import io.vertx.test.core.VertxTestBase;
import io.vertx.test.tls.Cert;
import io.vertx.test.tls.Trust;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSessionContext;
import java.util.*;

/**
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
public class SSLHelperTest extends VertxTestBase {

  private void testDefaultCiphers(HttpServerOptions httpServerOptions) {
    List<String> ciphers = new SSLHelper(httpServerOptions, Cert.CLIENT_JKS.get(), Trust.SERVER_JKS.get())
        .getContext((VertxInternal) vertx).cipherSuites();
    assertThat(ciphers.size(), anyOf(is(9), is(11)));
    assertThat(ciphers, hasItems("TLS_AES_256_GCM_SHA384"));
    assertThat(ciphers, not(hasItems("TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "DES-CBC3-SHA")));
  }

  @Test
  public void testDefaultJdkCiphers() {
    testDefaultCiphers(new HttpServerOptions());
  }

  @Test
  public void testDefaultOpenSslCiphers() {
    testDefaultCiphers(new HttpServerOptions().setOpenSslEngineOptions(new OpenSSLEngineOptions()));
  }

  @Test
  public void testDefaultOpenSslServerSessionContext() throws Exception {
    testOpenSslServerSessionContext(true);
  }

  @Test
  public void testUserSetOpenSslServerSessionContext() throws Exception {
    testOpenSslServerSessionContext(false);
  }

  private void testOpenSslServerSessionContext(boolean testDefault){
    HttpServerOptions httpServerOptions = new HttpServerOptions().setOpenSslEngineOptions(new OpenSSLEngineOptions());

    if(!testDefault) {
      httpServerOptions.setOpenSslEngineOptions(new OpenSSLEngineOptions().setSessionCacheEnabled(false));
    }

    SSLHelper defaultHelper = new SSLHelper(httpServerOptions,
            Cert.SERVER_PEM.get(),
            Trust.SERVER_PEM.get());

    SslContext ctx = defaultHelper.getContext((VertxInternal) vertx);
    assertTrue(ctx instanceof OpenSslServerContext);

    SSLSessionContext sslSessionContext = ctx.sessionContext();
    assertTrue(sslSessionContext instanceof OpenSslServerSessionContext);

    if (sslSessionContext instanceof OpenSslServerSessionContext) {
      assertEquals(testDefault, ((OpenSslServerSessionContext) sslSessionContext).isSessionCacheEnabled());
    }
  }

  @Test
  public void testPreserveEnabledCipherSuitesOrder() throws Exception {
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(null, null, null);
    SSLEngine engine = context.createSSLEngine();
    HttpServerOptions options = new HttpServerOptions();
    for (String suite : engine.getEnabledCipherSuites()) {
      options.addEnabledCipherSuite(suite);
    }
    assertEquals(new ArrayList<>(options.getEnabledCipherSuites()), Arrays.asList(engine.getEnabledCipherSuites()));
    assertEquals(new ArrayList<>(new HttpServerOptions(options).getEnabledCipherSuites()), Arrays.asList(engine.getEnabledCipherSuites()));
    JsonObject json = options.toJson();
    assertEquals(new ArrayList<>(new HttpServerOptions(json).getEnabledCipherSuites()), Arrays.asList(engine.getEnabledCipherSuites()));
    SSLHelper helper = new SSLHelper(options, Cert.SERVER_JKS.get(), null);
    assertEquals(Arrays.asList(helper.createEngine((VertxInternal) vertx).getEnabledCipherSuites()), Arrays.asList(engine.getEnabledCipherSuites()));
  }

  @Test
  public void testPreserveEnabledSecureTransportProtocolOrder() throws Exception {
    HttpServerOptions options = new HttpServerOptions();
    List<String> expectedProtocols = new ArrayList<>(options.getEnabledSecureTransportProtocols());

    options.removeEnabledSecureTransportProtocol("TLSv1");
    options.addEnabledSecureTransportProtocol("SSLv3");
    expectedProtocols.remove("TLSv1");
    expectedProtocols.add("SSLv3");

    assertEquals(new ArrayList<>(options.getEnabledSecureTransportProtocols()), expectedProtocols);
    assertEquals(new ArrayList<>(new HttpServerOptions(options).getEnabledSecureTransportProtocols()), expectedProtocols);
    JsonObject json = options.toJson();
    assertEquals(new ArrayList<>(new HttpServerOptions(json).getEnabledSecureTransportProtocols()), expectedProtocols);
  }
}
