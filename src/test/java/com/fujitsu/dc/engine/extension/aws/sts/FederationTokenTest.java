/**
 * Personium
 * Copyright 2016 FUJITSU LIMITED
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.fujitsu.dc.engine.extension.aws.sts;

import static org.fest.assertions.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.EcmaError;
import org.mozilla.javascript.NativeObject;
import org.mozilla.javascript.json.JsonParser;
import org.mozilla.javascript.json.JsonParser.ParseException;

import com.fujitsu.dc.engine.extension.support.ExtensionLogger;

/**
 * Ext_AWSSecurityTokenServiceTest. <br />
 * ※本テストを実行するにはsrc/test/resources配下に「test-config.properties」を配置してください。（内容は「test-config.properties.sample」を参考にしてください）
 */
public class FederationTokenTest {

    private static final int DURATION_SECONDS_MIN = 900;
    private static final int DURATION_SECONDS_MAX = 129600;

    private static final int PROCESSING_TIME = 3 * 60 * 1000;

    private static final int DEFAULT_DURATION_SECONDS = 43200;
    private static final long DEFAULT_DURATION_MILL_SECONDS = DEFAULT_DURATION_SECONDS * 1000;

    private static String accessKeyId;
    private String secretAccessKey;
    private String proxyHost;
    private int proxyPort;
    private String proxyUser;
    private String proxyPassword;

    /**
     * すべてのテスト実行前に１度だけ実行する.
     */
    @BeforeClass
    public static void beforeClass() {
        Ext_AWSSecurityTokenService.setLogger(Ext_AWSSecurityTokenService.class, new ExtensionLogger(
                Ext_AWSSecurityTokenService.class));
    }

    /**
     * @throws IOException プロパティのロードに失敗
     */
    @Before
    public void before() throws IOException {
        Properties properties = getProperties();

        accessKeyId = properties.getProperty("AccessKeyId");
        secretAccessKey = properties.getProperty("SecretAccessKey");
        proxyHost = properties.getProperty("ProxyHost", null);
        proxyPort = Integer.parseInt(properties.getProperty("ProxyPort", "80"));
        proxyUser = properties.getProperty("ProxyUser", null);
        proxyPassword = properties.getProperty("ProxyPassword", null);
    }

    /**
     * durationSecondsを省略した場合AWSFederationTokenが取得できること.
     * @throws Exception 実行中エラー
     */
    @Test
    public void durationSecondsを省略した場合AWSFederationTokenが取得できること() throws Exception {
        long current = System.currentTimeMillis();
        String name = "federatedUser";

        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        // Token取得
        NativeObject res = (NativeObject) stsService.getFederationToken(name, policy);

        // Credentials取得
        NativeObject credentials = (NativeObject) res.get("Credentials");
        assertThat(((String) credentials.get("AccessKeyId")).length()).isGreaterThanOrEqualTo(16);
        assertThat(((String) credentials.get("AccessKeyId")).length()).isLessThanOrEqualTo(32);
        assertThat(((String) credentials.get("SecretAccessKey")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((String) credentials.get("SessionToken")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((Double) credentials.get("Expiration"))).isGreaterThan(
                current + DEFAULT_DURATION_MILL_SECONDS - PROCESSING_TIME);
        assertThat(((Double) credentials.get("Expiration"))).isLessThan(
                current + DEFAULT_DURATION_MILL_SECONDS + PROCESSING_TIME);
        // FederatedUser取得
        NativeObject federatedUser = (NativeObject) res.get("FederatedUser");
        assertThat(((String) federatedUser.get("Arn")).length()).isGreaterThanOrEqualTo(20);
        assertThat(((String) federatedUser.get("Arn")).length()).isLessThanOrEqualTo(2048);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isGreaterThanOrEqualTo(2);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isLessThanOrEqualTo(96);
        // PackedPolicySize取得
        assertThat(res.get("PackedPolicySize")).isInstanceOf(Integer.class);
    }

    /**
     * durationSecondsを指定した場合AWSFederationTokenが取得できること.
     * @throws Exception 実行中エラー
     */
    @Test
    public void durationSecondsを指定した場合AWSFederationTokenが取得できること() throws Exception {
        int durationSeconds = DURATION_SECONDS_MIN;
        long current = System.currentTimeMillis();
        String name = "federatedUser";

        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        // Token取得
        NativeObject res = (NativeObject) stsService.getFederationTokenWithDuration(name, policy, durationSeconds);

        // Credentials取得
        NativeObject credentials = (NativeObject) res.get("Credentials");
        assertThat(((String) credentials.get("AccessKeyId")).length()).isGreaterThanOrEqualTo(16);
        assertThat(((String) credentials.get("AccessKeyId")).length()).isLessThanOrEqualTo(32);
        assertThat(((String) credentials.get("SecretAccessKey")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((String) credentials.get("SessionToken")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((Double) credentials.get("Expiration"))).isGreaterThan(
                current + durationSeconds * 1000 - PROCESSING_TIME);
        assertThat(((Double) credentials.get("Expiration"))).isLessThan(
                current + durationSeconds * 1000 + PROCESSING_TIME);
        // FederatedUser取得
        NativeObject federatedUser = (NativeObject) res.get("FederatedUser");
        assertThat(((String) federatedUser.get("Arn")).length()).isGreaterThanOrEqualTo(20);
        assertThat(((String) federatedUser.get("Arn")).length()).isLessThanOrEqualTo(2048);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isGreaterThanOrEqualTo(2);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isLessThanOrEqualTo(96);
        // PackedPolicySize取得
        assertThat(res.get("PackedPolicySize")).isInstanceOf(Integer.class);
    }

    /**
     * AccessKeyIdを省略した場合EcmaErrorエラーとなること.
     * @throws ParseException JSONのパースエラー
     */
    @Test(expected = EcmaError.class)
    public void AccessKeyIdを省略した場合EcmaErrorエラーとなること() throws ParseException {
        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        String name = "federatedUser";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        // Token取得
        stsService.getFederationToken(name, policy);
    }

    /**
     * AccessKeyIdに存在しないIDを指定した場合EcmaErrorエラーとなること.
     * @throws ParseException JSONのパースエラー
     */
    @Test(expected = EcmaError.class)
    public void AccessKeyIdに存在しないIDを指定した場合EcmaErrorエラーとなること() throws ParseException {
        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId("dummyAccessKeyId");
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        String name = "federatedUser";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        // Token取得
        stsService.getFederationToken(name, policy);
    }

    /**
     * AccessKeyIdに空文字を指定した場合EcmaErrorエラーとなること.
     * @throws ParseException JSONのパースエラー
     */
    @Test(expected = EcmaError.class)
    public void AccessKeyIdに空文字を指定した場合EcmaErrorエラーとなること() throws ParseException {
        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId("");
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        String name = "federatedUser";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        // Token取得
        stsService.getFederationToken(name, policy);
    }

    /**
     * AccessKeyIdにnullを指定した場合EcmaErrorエラーとなること.
     * @throws ParseException JSONのパースエラー
     */
    @Test(expected = EcmaError.class)
    public void AccessKeyIdにnullを指定した場合EcmaErrorエラーとなること() throws ParseException {
        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(null);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        String name = "federatedUser";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        // Token取得
        stsService.getFederationToken(name, policy);
    }

    /**
     * SecretAccessKeyを省略した場合EcmaErrorエラーとなること.
     * @throws ParseException JSONのパースエラー
     */
    @Test(expected = EcmaError.class)
    public void SecretAccessKeyを省略した場合EcmaErrorエラーとなること() throws ParseException {
        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        String name = "federatedUser";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        // Token取得
        stsService.getFederationToken(name, policy);
    }

    /**
     * SecretAccessKeyに誤ったSecretAccessKeyを指定した場合EcmaErrorエラーとなること.
     * @throws ParseException JSONのパースエラー
     */
    @Test(expected = EcmaError.class)
    public void SecretAccessKeyに誤ったSecretAccessKeyを指定した場合EcmaErrorエラーとなること() throws ParseException {
        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey("dummySecretAccessKey");
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        String name = "federatedUser";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        // Token取得
        stsService.getFederationToken(name, policy);
    }

    /**
     * SecretAccessKeyに空文字を指定した場合EcmaErrorエラーとなること.
     * @throws ParseException JSONのパースエラー
     */
    @Test(expected = EcmaError.class)
    public void SecretAccessKeyに空文字を指定した場合EcmaErrorエラーとなること() throws ParseException {
        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey("");
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        String name = "federatedUser";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        // Token取得
        stsService.getFederationToken(name, policy);
    }

    /**
     * SecretAccessKeyにnullを指定した場合EcmaErrorエラーとなること.
     * @throws ParseException JSONのパースエラー
     */
    @Test(expected = EcmaError.class)
    public void SecretAccessKeyにnullを指定した場合EcmaErrorエラーとなること() throws ParseException {
        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(null);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        String name = "federatedUser";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        // Token取得
        stsService.getFederationToken(name, policy);
    }

    /**
     * Regionを省略した場合トークンを取得できること.
     * @throws ParseException JSONパースエラー
     */
    @Test
    public void Regionを省略した場合トークンを取得できること() throws ParseException {
        long current = System.currentTimeMillis();
        String name = "federatedUser";

        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        // Token取得
        NativeObject res = (NativeObject) stsService.getFederationToken(name, policy);

        // Credentials取得
        NativeObject credentials = (NativeObject) res.get("Credentials");
        assertThat(((String) credentials.get("AccessKeyId")).length()).isGreaterThanOrEqualTo(16);
        assertThat(((String) credentials.get("AccessKeyId")).length()).isLessThanOrEqualTo(32);
        assertThat(((String) credentials.get("SecretAccessKey")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((String) credentials.get("SessionToken")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((Double) credentials.get("Expiration"))).isGreaterThan(
                current + DEFAULT_DURATION_MILL_SECONDS - PROCESSING_TIME);
        assertThat(((Double) credentials.get("Expiration"))).isLessThan(
                current + DEFAULT_DURATION_MILL_SECONDS + PROCESSING_TIME);
        // FederatedUser取得
        NativeObject federatedUser = (NativeObject) res.get("FederatedUser");
        assertThat(((String) federatedUser.get("Arn")).length()).isGreaterThanOrEqualTo(20);
        assertThat(((String) federatedUser.get("Arn")).length()).isLessThanOrEqualTo(2048);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isGreaterThanOrEqualTo(2);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isLessThanOrEqualTo(96);
        // PackedPolicySize取得
        assertThat(res.get("PackedPolicySize")).isInstanceOf(Integer.class);
    }

    /**
     * RegionにDEFAULT_REGIONを指定した場合トークンを取得できること.
     * @throws ParseException JSONパースエラー
     */
    @Test
    public void RegionにDEFAULT_REGIONを指定した場合トークンを取得できること() throws ParseException {
        String region = "DEFAULT_REGION";
        long current = System.currentTimeMillis();
        String name = "federatedUser";

        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);
        stsService.jsSet_Region(region);

        // Token取得
        NativeObject res = (NativeObject) stsService.getFederationToken(name, policy);

        // Credentials取得
        NativeObject credentials = (NativeObject) res.get("Credentials");
        assertThat(((String) credentials.get("AccessKeyId")).length()).isGreaterThanOrEqualTo(16);
        assertThat(((String) credentials.get("AccessKeyId")).length()).isLessThanOrEqualTo(32);
        assertThat(((String) credentials.get("SecretAccessKey")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((String) credentials.get("SessionToken")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((Double) credentials.get("Expiration"))).isGreaterThan(
                current + DEFAULT_DURATION_MILL_SECONDS - PROCESSING_TIME);
        assertThat(((Double) credentials.get("Expiration"))).isLessThan(
                current + DEFAULT_DURATION_MILL_SECONDS + PROCESSING_TIME);
        // FederatedUser取得
        NativeObject federatedUser = (NativeObject) res.get("FederatedUser");
        assertThat(((String) federatedUser.get("Arn")).length()).isGreaterThanOrEqualTo(20);
        assertThat(((String) federatedUser.get("Arn")).length()).isLessThanOrEqualTo(2048);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isGreaterThanOrEqualTo(2);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isLessThanOrEqualTo(96);
        // PackedPolicySize取得
        assertThat(res.get("PackedPolicySize")).isInstanceOf(Integer.class);

    }

    /**
     * RegionにGovCloudを指定した場合トークンを取得できること.
     * @throws ParseException JSONパースエラー
     */
    @Test
    public void RegionにGovCloudを指定した場合トークンを取得できること() throws ParseException {
        String region = "GovCloud";
        long current = System.currentTimeMillis();
        String name = "federatedUser";

        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);
        stsService.jsSet_Region(region);

        // Token取得
        NativeObject res = (NativeObject) stsService.getFederationToken(name, policy);

        // Credentials取得
        NativeObject credentials = (NativeObject) res.get("Credentials");
        assertThat(((String) credentials.get("AccessKeyId")).length()).isGreaterThanOrEqualTo(16);
        assertThat(((String) credentials.get("AccessKeyId")).length()).isLessThanOrEqualTo(32);
        assertThat(((String) credentials.get("SecretAccessKey")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((String) credentials.get("SessionToken")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((Double) credentials.get("Expiration"))).isGreaterThan(
                current + DEFAULT_DURATION_MILL_SECONDS - PROCESSING_TIME);
        assertThat(((Double) credentials.get("Expiration"))).isLessThan(
                current + DEFAULT_DURATION_MILL_SECONDS + PROCESSING_TIME);
        // FederatedUser取得
        NativeObject federatedUser = (NativeObject) res.get("FederatedUser");
        assertThat(((String) federatedUser.get("Arn")).length()).isGreaterThanOrEqualTo(20);
        assertThat(((String) federatedUser.get("Arn")).length()).isLessThanOrEqualTo(2048);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isGreaterThanOrEqualTo(2);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isLessThanOrEqualTo(96);
        // PackedPolicySize取得
        assertThat(res.get("PackedPolicySize")).isInstanceOf(Integer.class);
    }

    /**
     * RegionにAP_NORTHEAST_1を指定した場合トークンを取得できること.
     * @throws ParseException JSONパースエラー
     */
    @Test
    public void RegionにAP_NORTHEAST_1を指定した場合トークンを取得できること() throws ParseException {
        String region = "AP_NORTHEAST_1";
        long current = System.currentTimeMillis();
        String name = "federatedUser";

        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);
        stsService.jsSet_Region(region);

        // Token取得
        NativeObject res = (NativeObject) stsService.getFederationToken(name, policy);

        // Credentials取得
        NativeObject credentials = (NativeObject) res.get("Credentials");
        assertThat(((String) credentials.get("AccessKeyId")).length()).isGreaterThanOrEqualTo(16);
        assertThat(((String) credentials.get("AccessKeyId")).length()).isLessThanOrEqualTo(32);
        assertThat(((String) credentials.get("SecretAccessKey")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((String) credentials.get("SessionToken")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((Double) credentials.get("Expiration"))).isGreaterThan(
                current + DEFAULT_DURATION_MILL_SECONDS - PROCESSING_TIME);
        assertThat(((Double) credentials.get("Expiration"))).isLessThan(
                current + DEFAULT_DURATION_MILL_SECONDS + PROCESSING_TIME);
        // FederatedUser取得
        NativeObject federatedUser = (NativeObject) res.get("FederatedUser");
        assertThat(((String) federatedUser.get("Arn")).length()).isGreaterThanOrEqualTo(20);
        assertThat(((String) federatedUser.get("Arn")).length()).isLessThanOrEqualTo(2048);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isGreaterThanOrEqualTo(2);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isLessThanOrEqualTo(96);
        // PackedPolicySize取得
        assertThat(res.get("PackedPolicySize")).isInstanceOf(Integer.class);
    }

    /**
     * Regionに誤ったRegionを指定した場合無視されてトークンを取得できること.
     * @throws ParseException JSONパースエラー
     */
    @Test
    public void Regionに誤ったRegionを指定した場合無視されてトークンを取得できること() throws ParseException {
        String region = "DUMMY_REGION";
        long current = System.currentTimeMillis();
        String name = "federatedUser";

        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);
        stsService.jsSet_Region(region);

        // Token取得
        NativeObject res = (NativeObject) stsService.getFederationToken(name, policy);

        // Credentials取得
        NativeObject credentials = (NativeObject) res.get("Credentials");
        assertThat(((String) credentials.get("AccessKeyId")).length()).isGreaterThanOrEqualTo(16);
        assertThat(((String) credentials.get("AccessKeyId")).length()).isLessThanOrEqualTo(32);
        assertThat(((String) credentials.get("SecretAccessKey")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((String) credentials.get("SessionToken")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((Double) credentials.get("Expiration"))).isGreaterThan(
                current + DEFAULT_DURATION_MILL_SECONDS - PROCESSING_TIME);
        assertThat(((Double) credentials.get("Expiration"))).isLessThan(
                current + DEFAULT_DURATION_MILL_SECONDS + PROCESSING_TIME);
        // FederatedUser取得
        NativeObject federatedUser = (NativeObject) res.get("FederatedUser");
        assertThat(((String) federatedUser.get("Arn")).length()).isGreaterThanOrEqualTo(20);
        assertThat(((String) federatedUser.get("Arn")).length()).isLessThanOrEqualTo(2048);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isGreaterThanOrEqualTo(2);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isLessThanOrEqualTo(96);
        // PackedPolicySize取得
        assertThat(res.get("PackedPolicySize")).isInstanceOf(Integer.class);
    }

    /**
     * Regionに空文字を指定した場合無視されてトークンを取得できること.
     * @throws ParseException JSONパースエラー
     */
    @Test
    public void Regionに空文字を指定した場合無視されてトークンを取得できること() throws ParseException {
        String region = "";
        long current = System.currentTimeMillis();
        String name = "federatedUser";

        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);
        stsService.jsSet_Region(region);

        // Token取得
        NativeObject res = (NativeObject) stsService.getFederationToken(name, policy);

        // Credentials取得
        NativeObject credentials = (NativeObject) res.get("Credentials");
        assertThat(((String) credentials.get("AccessKeyId")).length()).isGreaterThanOrEqualTo(16);
        assertThat(((String) credentials.get("AccessKeyId")).length()).isLessThanOrEqualTo(32);
        assertThat(((String) credentials.get("SecretAccessKey")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((String) credentials.get("SessionToken")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((Double) credentials.get("Expiration"))).isGreaterThan(
                current + DEFAULT_DURATION_MILL_SECONDS - PROCESSING_TIME);
        assertThat(((Double) credentials.get("Expiration"))).isLessThan(
                current + DEFAULT_DURATION_MILL_SECONDS + PROCESSING_TIME);
        // FederatedUser取得
        NativeObject federatedUser = (NativeObject) res.get("FederatedUser");
        assertThat(((String) federatedUser.get("Arn")).length()).isGreaterThanOrEqualTo(20);
        assertThat(((String) federatedUser.get("Arn")).length()).isLessThanOrEqualTo(2048);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isGreaterThanOrEqualTo(2);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isLessThanOrEqualTo(96);
        // PackedPolicySize取得
        assertThat(res.get("PackedPolicySize")).isInstanceOf(Integer.class);
    }

    /**
     * Regionにnull文字を指定した場合無視されてトークンを取得できること.
     * @throws ParseException JSONパースエラー
     */
    @Test
    public void Regionにnullを指定した場合無視されてトークンを取得できること() throws ParseException {
        String region = null;
        long current = System.currentTimeMillis();
        String name = "federatedUser";

        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);
        stsService.jsSet_Region(region);

        // Token取得
        NativeObject res = (NativeObject) stsService.getFederationToken(name, policy);

        // Credentials取得
        NativeObject credentials = (NativeObject) res.get("Credentials");
        assertThat(((String) credentials.get("AccessKeyId")).length()).isGreaterThanOrEqualTo(16);
        assertThat(((String) credentials.get("AccessKeyId")).length()).isLessThanOrEqualTo(32);
        assertThat(((String) credentials.get("SecretAccessKey")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((String) credentials.get("SessionToken")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((Double) credentials.get("Expiration"))).isGreaterThan(
                current + DEFAULT_DURATION_MILL_SECONDS - PROCESSING_TIME);
        assertThat(((Double) credentials.get("Expiration"))).isLessThan(
                current + DEFAULT_DURATION_MILL_SECONDS + PROCESSING_TIME);
        // FederatedUser取得
        NativeObject federatedUser = (NativeObject) res.get("FederatedUser");
        assertThat(((String) federatedUser.get("Arn")).length()).isGreaterThanOrEqualTo(20);
        assertThat(((String) federatedUser.get("Arn")).length()).isLessThanOrEqualTo(2048);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isGreaterThanOrEqualTo(2);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isLessThanOrEqualTo(96);
        // PackedPolicySize取得
        assertThat(res.get("PackedPolicySize")).isInstanceOf(Integer.class);
    }

    /**
     * ProxyHostに不正な文字列を指定した場合EcmaErrorとなること.
     * @throws ParseException JSONパースエラー
     */
    @Test(expected = EcmaError.class)
    public void ProxyHostに不正な文字列を指定した場合EcmaErrorとなること() throws ParseException {
        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost("example.dummy.proxy");
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        String name = "federatedUser";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        // Token取得
        stsService.getFederationToken(name, policy);
    }

    /**
     * nameが空文字の場合EcmaErrorとなること.
     * @throws ParseException JSONパースエラー
     */
    @Test(expected = EcmaError.class)
    public void nameが空文字の場合EcmaErrorとなること() throws ParseException {
        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        String name = "";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        // Token取得
        stsService.getFederationToken(name, policy);
    }

    /**
     * nameがnullの場合EcmaErrorとなること.
     * @throws ParseException JSONパースエラー
     */
    @Test(expected = EcmaError.class)
    public void nameがnullの場合EcmaErrorとなること() throws ParseException {
        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        String name = null;
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        // Token取得
        stsService.getFederationToken(name, policy);
    }

    /**
     * nameの文字数が連携ユーザ名の最小値より小さい場合EcmaErrorとなること.
     * @throws ParseException JSONパースエラー
     */
    @Test(expected = EcmaError.class)
    public void nameの文字数が連携ユーザ名の最小値より小さい場合EcmaErrorとなること() throws ParseException {
        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        // 最小値が2文字なので、1文字を指定
        String name = "1";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        // Token取得
        stsService.getFederationToken(name, policy);
    }

    /**
     * nameの文字数が連携ユーザ名の最小値である場合FederationTokenを取得できること.
     * @throws ParseException JSONパースエラー
     */
    @Test
    public void nameの文字数が連携ユーザ名の最小値である場合FederationTokenを取得できること() throws ParseException {
        long current = System.currentTimeMillis();

        // 最小値が2文字なので、2文字を指定
        String name = "12";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        // Token取得
        NativeObject res = (NativeObject) stsService.getFederationToken(name, policy);

        // Credentials取得
        NativeObject credentials = (NativeObject) res.get("Credentials");
        assertThat(((String) credentials.get("AccessKeyId")).length()).isGreaterThanOrEqualTo(16);
        assertThat(((String) credentials.get("AccessKeyId")).length()).isLessThanOrEqualTo(32);
        assertThat(((String) credentials.get("SecretAccessKey")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((String) credentials.get("SessionToken")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((Double) credentials.get("Expiration"))).isGreaterThan(
                current + DEFAULT_DURATION_MILL_SECONDS - PROCESSING_TIME);
        assertThat(((Double) credentials.get("Expiration"))).isLessThan(
                current + DEFAULT_DURATION_MILL_SECONDS + PROCESSING_TIME);
        // FederatedUser取得
        NativeObject federatedUser = (NativeObject) res.get("FederatedUser");
        assertThat(((String) federatedUser.get("Arn")).length()).isGreaterThanOrEqualTo(20);
        assertThat(((String) federatedUser.get("Arn")).length()).isLessThanOrEqualTo(2048);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isGreaterThanOrEqualTo(2);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isLessThanOrEqualTo(96);
        // PackedPolicySize取得
        assertThat(res.get("PackedPolicySize")).isInstanceOf(Integer.class);
    }

    /**
     * nameの文字数が連携ユーザ名の最大値である場合FederationTokenを取得できること.
     * @throws ParseException JSONパースエラー
     */
    @Test
    public void nameの文字数が連携ユーザ名の最大値である場合FederationTokenを取得できること() throws ParseException {
        long current = System.currentTimeMillis();

        // 最大値が32文字なので、32文字を指定
        String name = "12345678901234567890123456789012";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        // Token取得
        NativeObject res = (NativeObject) stsService.getFederationToken(name, policy);

        // Credentials取得
        NativeObject credentials = (NativeObject) res.get("Credentials");
        assertThat(((String) credentials.get("AccessKeyId")).length()).isGreaterThanOrEqualTo(16);
        assertThat(((String) credentials.get("AccessKeyId")).length()).isLessThanOrEqualTo(32);
        assertThat(((String) credentials.get("SecretAccessKey")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((String) credentials.get("SessionToken")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((Double) credentials.get("Expiration"))).isGreaterThan(
                current + DEFAULT_DURATION_MILL_SECONDS - PROCESSING_TIME);
        assertThat(((Double) credentials.get("Expiration"))).isLessThan(
                current + DEFAULT_DURATION_MILL_SECONDS + PROCESSING_TIME);
        // FederatedUser取得
        NativeObject federatedUser = (NativeObject) res.get("FederatedUser");
        assertThat(((String) federatedUser.get("Arn")).length()).isGreaterThanOrEqualTo(20);
        assertThat(((String) federatedUser.get("Arn")).length()).isLessThanOrEqualTo(2048);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isGreaterThanOrEqualTo(2);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isLessThanOrEqualTo(96);
        // PackedPolicySize取得
        assertThat(res.get("PackedPolicySize")).isInstanceOf(Integer.class);
    }

    /**
     * nameの文字数が連携ユーザ名の最大値より大きい場合EcmaErrorとなること.
     * @throws ParseException JSONパースエラー
     */
    @Test(expected = EcmaError.class)
    public void nameの文字数が連携ユーザ名の最大値より大きい場合EcmaErrorとなること() throws ParseException {
        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        // 最大値が32文字なので、33文字を指定
        String name = "123456789012345678901234567890123";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        // Token取得
        stsService.getFederationToken(name, policy);
    }

    /**
     * policyがnullの場合EcmaErrorとなること.
     * @throws ParseException JSONパースエラー
     */
    @Test(expected = EcmaError.class)
    public void policyがnullの場合EcmaErrorとなること() throws ParseException {
        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        String name = "federationUser";
        NativeObject policy = null;

        // Token取得
        stsService.getFederationToken(name, policy);

    }

    /**
     * policy内のキーワードがAWSに定義されているものではない場合EcmaErrorとなること.
     * @throws ParseException JSONパースエラー
     */
    @Test(expected = EcmaError.class)
    public void policy内のキーワードがAWSに定義されているものではない場合EcmaErrorとなること() throws ParseException {
        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        String name = "federationUser";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Sttement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        // Token取得
        stsService.getFederationToken(name, policy);
    }

    /**
     * policy内のStatementが2つ以上存在する場合FederationTokenを取得できること.
     * @throws ParseException JSONパースエラー
     */
    @Test
    public void policy内のStatementが2つ以上存在する場合FederationTokenを取得できること() throws ParseException {
        long current = System.currentTimeMillis();

        String name = "federationUser";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sqs:SendMessage\",\"Resource\":\"*\"},"
                        + "{\"Effect\":\"Allow\",\"Action\":\"sqs:ReceiveMessage\",\"Resource\":\"*\"},"
                        + "{\"Effect\":\"Allow\","
                        + "\"Action\":[\"sqs:SendMessage\",\"sqs:ReceiveMessage\"],\"Resource\":\"*\"}]}");

        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        // Token取得
        NativeObject res = (NativeObject) stsService.getFederationToken(name, policy);

        // Credentials取得
        NativeObject credentials = (NativeObject) res.get("Credentials");
        assertThat(((String) credentials.get("AccessKeyId")).length()).isGreaterThanOrEqualTo(16);
        assertThat(((String) credentials.get("AccessKeyId")).length()).isLessThanOrEqualTo(32);
        assertThat(((String) credentials.get("SecretAccessKey")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((String) credentials.get("SessionToken")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((Double) credentials.get("Expiration"))).isGreaterThan(
                current + DEFAULT_DURATION_MILL_SECONDS - PROCESSING_TIME);
        assertThat(((Double) credentials.get("Expiration"))).isLessThan(
                current + DEFAULT_DURATION_MILL_SECONDS + PROCESSING_TIME);
        // FederatedUser取得
        NativeObject federatedUser = (NativeObject) res.get("FederatedUser");
        assertThat(((String) federatedUser.get("Arn")).length()).isGreaterThanOrEqualTo(20);
        assertThat(((String) federatedUser.get("Arn")).length()).isLessThanOrEqualTo(2048);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isGreaterThanOrEqualTo(2);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isLessThanOrEqualTo(96);
        // PackedPolicySize取得
        assertThat(res.get("PackedPolicySize")).isInstanceOf(Integer.class);
    }

    /**
     * durationSecondsに指定可能な最小値よりも小さい値を指定した場合EcmaErrorとなること.
     * @throws Exception 実行中エラー
     */
    @Test(expected = EcmaError.class)
    public void durationSecondsに指定可能な最小値よりも小さい値を指定した場合EcmaErrorとなること() throws Exception {
        int durationSeconds = DURATION_SECONDS_MIN - 1;

        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        String name = "federatedUser";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        // Token取得
        stsService.getFederationTokenWithDuration(name, policy, durationSeconds);
    }

    /**
     * durationSecondsに指定可能な最小値を指定した場合トークンを取得できること.
     * @throws Exception 実行中エラー
     */
    @Test
    public void durationSecondsに指定可能な最小値を指定した場合トークンを取得できること() throws Exception {
        int durationSeconds = DURATION_SECONDS_MIN;
        long current = System.currentTimeMillis();
        String name = "federatedUser";

        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        // Token取得
        NativeObject res = (NativeObject) stsService.getFederationTokenWithDuration(name, policy, durationSeconds);

        // Credentials取得
        NativeObject credentials = (NativeObject) res.get("Credentials");
        assertThat(((String) credentials.get("AccessKeyId")).length()).isGreaterThanOrEqualTo(16);
        assertThat(((String) credentials.get("AccessKeyId")).length()).isLessThanOrEqualTo(32);
        assertThat(((String) credentials.get("SecretAccessKey")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((String) credentials.get("SessionToken")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((Double) credentials.get("Expiration"))).isGreaterThan(
                current + durationSeconds * 1000 - PROCESSING_TIME);
        assertThat(((Double) credentials.get("Expiration"))).isLessThan(
                current + durationSeconds * 1000 + PROCESSING_TIME);
        // FederatedUser取得
        NativeObject federatedUser = (NativeObject) res.get("FederatedUser");
        assertThat(((String) federatedUser.get("Arn")).length()).isGreaterThanOrEqualTo(20);
        assertThat(((String) federatedUser.get("Arn")).length()).isLessThanOrEqualTo(2048);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isGreaterThanOrEqualTo(2);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isLessThanOrEqualTo(96);
        // PackedPolicySize取得
        assertThat(res.get("PackedPolicySize")).isInstanceOf(Integer.class);
    }

    /**
     * durationSecondsに指定可能な最大値を指定した場合トークンを取得できること.
     * @throws Exception 実行中エラー
     */
    @Test
    public void durationSecondsに指定可能な最大値を指定した場合トークンを取得できること() throws Exception {
        int durationSeconds = DURATION_SECONDS_MAX;
        long current = System.currentTimeMillis();
        String name = "federatedUser";

        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        // Token取得
        NativeObject res = (NativeObject) stsService.getFederationTokenWithDuration(name, policy, durationSeconds);

        // Credentials取得
        NativeObject credentials = (NativeObject) res.get("Credentials");
        assertThat(((String) credentials.get("AccessKeyId")).length()).isGreaterThanOrEqualTo(16);
        assertThat(((String) credentials.get("AccessKeyId")).length()).isLessThanOrEqualTo(32);
        assertThat(((String) credentials.get("SecretAccessKey")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((String) credentials.get("SessionToken")).length()).isGreaterThanOrEqualTo(1);
        assertThat(((Double) credentials.get("Expiration"))).isGreaterThan(
                current + durationSeconds * 1000 - PROCESSING_TIME);
        assertThat(((Double) credentials.get("Expiration"))).isLessThan(
                current + durationSeconds * 1000 + PROCESSING_TIME);
        // FederatedUser取得
        NativeObject federatedUser = (NativeObject) res.get("FederatedUser");
        assertThat(((String) federatedUser.get("Arn")).length()).isGreaterThanOrEqualTo(20);
        assertThat(((String) federatedUser.get("Arn")).length()).isLessThanOrEqualTo(2048);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isGreaterThanOrEqualTo(2);
        assertThat(((String) federatedUser.get("FederatedUserId")).length()).isLessThanOrEqualTo(96);
        // PackedPolicySize取得
        assertThat(res.get("PackedPolicySize")).isInstanceOf(Integer.class);
    }

    /**
     * durationSecondsに指定可能な最大値よりも大きい値を指定した場合EcmaErrorとなること.
     * @throws Exception 実行中エラー
     */
    @Test(expected = EcmaError.class)
    public void durationSecondsに指定可能な最大値よりも大きい値を指定した場合EcmaErrorとなること() throws Exception {
        int durationSeconds = DURATION_SECONDS_MAX + 1;

        Ext_AWSSecurityTokenService stsService = new Ext_AWSSecurityTokenService();
        stsService.jsSet_AccessKeyId(accessKeyId);
        stsService.jsSet_SecretAccessKey(secretAccessKey);
        stsService.jsSet_ProxyHost(proxyHost);
        stsService.jsSet_ProxyPort(proxyPort);
        stsService.jsSet_ProxyUser(proxyUser);
        stsService.jsSet_ProxyPassword(proxyPassword);

        String name = "federatedUser";
        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        NativeObject policy = (NativeObject) p
                .parseValue("{\"Statement\": [{\"Effect\": \"Allow\",\"Action\": \"sqs:*\",\"Resource\": \"*\"}]}");

        // Token取得
        stsService.getFederationTokenWithDuration(name, policy, durationSeconds);
    }

    private Properties getProperties() throws IOException {
        Properties properties = new Properties();
        String propFileName = "test-config.properties";
        InputStream propStream = null;
        propStream = this.getClass().getClassLoader().getResourceAsStream(propFileName);
        if (null != propStream) {
            properties.load(propStream);
        }
        return properties;
    }
}
