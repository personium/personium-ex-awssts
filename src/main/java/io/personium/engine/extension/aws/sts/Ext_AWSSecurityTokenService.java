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
package io.personium.engine.extension.aws.sts;

import java.util.Map.Entry;

import org.json.simple.JSONObject;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.NativeObject;
import org.mozilla.javascript.annotations.JSConstructor;
import org.mozilla.javascript.annotations.JSFunction;
import org.mozilla.javascript.annotations.JSGetter;
import org.mozilla.javascript.json.JsonParser;
import org.mozilla.javascript.json.JsonParser.ParseException;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.amazonaws.services.securitytoken.model.FederatedUser;
import com.amazonaws.services.securitytoken.model.GetFederationTokenRequest;
import com.amazonaws.services.securitytoken.model.GetFederationTokenResult;
import com.amazonaws.services.securitytoken.model.GetSessionTokenRequest;
import com.amazonaws.services.securitytoken.model.GetSessionTokenResult;
import io.personium.engine.extension.support.AbstractExtensionScriptableObject;
import io.personium.engine.extension.support.ExtensionErrorConstructor;

/**
 * Engine-Extension AWS STS機能.
 */
@SuppressWarnings("serial")
public class Ext_AWSSecurityTokenService extends AbstractExtensionScriptableObject {

    private String accessKeyId;
    private String secretAccessKey;
    private String region;
    private String proxyHost;
    private int proxyPort;
    private String proxyUser;
    private String proxyPassword;

    /**
     * @return AWS認証情報(secret)
     */
    @JSGetter
    public String AccessKeyId() {
        return secretAccessKey;
    }

    /**
     * @param val AWS認証情報(key)
     */
    public void jsSet_AccessKeyId(String val) {
        this.accessKeyId = val;
    }

    /**
     * @return AWS認証情報(secret)
     */
    @JSGetter
    public String SecretAccessKey() {
        return secretAccessKey;
    }

    /**
     * @param val AWS認証情報(secret)
     */
    public void jsSet_SecretAccessKey(String val) {
        this.secretAccessKey = val;
    }

    /**
     * @return AWS Security Token Serviceを利用するリージョン名
     */
    @JSGetter
    public String Region() {
        return region;
    }

    /**
     * AWS Security Token Serviceを利用するリージョン名を設定する. <br />
     * ただし本機能(AWS STSを利用)では 2014/11/10現在、どの指定を行っても GovCloudに向く。
     * @param val AWS Security Token Serviceを利用するリージョン名
     */
    public void jsSet_Region(String val) {
        this.region = val;
    }

    /**
     * @return proxyサーバのアドレス/IP
     */
    @JSGetter
    public String ProxyHost() {
        return proxyHost;
    }

    /**
     * @param val proxyサーバのアドレス/IP
     */
    public void jsSet_ProxyHost(String val) {
        this.proxyHost = val;
    }

    /**
     * @return proxyサーバのポート番号
     */
    @JSGetter
    public int ProxyPort() {
        return proxyPort;
    }

    /**
     * @param val proxyサーバのポート番号
     */
    public void jsSet_ProxyPort(int val) {
        this.proxyPort = val;
    }

    /**
     * @return 認証ユーザID
     */
    @JSGetter
    public String ProxyUser() {
        return proxyUser;
    }

    /**
     * 認証プロキシを使用する場合に設定するユーザID.
     * @param val 認証ユーザID
     */
    public void jsSet_ProxyUser(String val) {
        this.proxyUser = val;
    }

    /**
     * @return 認証パスワード
     */
    @JSGetter
    public String ProxyPassword() {
        return proxyPassword;
    }

    /**
     * 認証プロキシを使用する場合に設定するパスワード.
     * @param val 認証パスワード
     */
    public void jsSet_ProxyPassword(String val) {
        this.proxyPassword = val;
    }

    @Override
    public String getClassName() {
        return "AWSSecurityTokenService";
    }

    /**
     * コンストラクタ.
     */
    @JSConstructor
    public Ext_AWSSecurityTokenService() {
    }

    /**
     * Session Tokenを取得する.
     * @return Session Token
     */
    @JSFunction
    public NativeObject getSessionToken() {
        return getSessionTokenWithDuration(null);
    }

    /**
     * Session Tokenを取得する.
     * @param durationSeconds 認証情報の有効期間（秒）
     * @return Session Token
     */
    @JSFunction
    public NativeObject getSessionTokenWithDuration(Integer durationSeconds) {

        ClientConfiguration clientConfig = createClientConfigration();

        try {
            // SecurityTokenServiceClientの設定
            AWSSecurityTokenServiceClient sts = new AWSSecurityTokenServiceClient(
                    new BasicAWSCredentials(this.accessKeyId, SecretAccessKey()), clientConfig);

            // GetSessionToken
            GetSessionTokenRequest req = new GetSessionTokenRequest();
            if (durationSeconds != null) {
                req.setDurationSeconds(durationSeconds);
            }
            GetSessionTokenResult res = sts.getSessionToken(req);

            // JSON形式のレスポンスの作成
            NativeObject sessionTokenJson = createJsonResponse(res);

            return sessionTokenJson;
        } catch (IllegalArgumentException e1) {
            this.getLogger().info(e1.getMessage(), e1);
            throw ExtensionErrorConstructor.construct(e1.toString());
        } catch (AmazonServiceException e1) {
            this.getLogger().info(e1.getMessage(), e1);
            throw ExtensionErrorConstructor.construct(e1.toString());
        } catch (AmazonClientException e1) {
            this.getLogger().info(e1.getMessage(), e1);
            throw ExtensionErrorConstructor.construct(e1.toString());
        } catch (ParseException e1) {
            // レスポンスの整形に失敗した場合
            this.getLogger().error("Failed to create session token response." + e1.getMessage());
            throw ExtensionErrorConstructor.construct(e1.toString());
        }
    }

    /**
     * Federation Tokenを取得する.
     * @param name 連携ユーザ名
     * @param policy AWSのIAMポリシー(JSON形式)
     * @return Federation Token
     */
    @JSFunction
    public NativeObject getFederationToken(String name, NativeObject policy) {
        return getFederationTokenWithDuration(name, policy, null);
    }

    /**
     * Federation Tokenを取得する.
     * @param name 連携ユーザ名
     * @param policy AWSのIAMポリシー(JSON形式)
     * @param durationSeconds 認証情報の有効期間（秒）
     * @return Session Token
     */
    @SuppressWarnings("unchecked")
    @JSFunction
    public NativeObject getFederationTokenWithDuration(String name, NativeObject policy, Integer durationSeconds) {

        // policyの形式チェック
        if (null == policy) {
            throw ExtensionErrorConstructor.construct("policy cannot be null.");
        }
        JSONObject jsonPolicy = new JSONObject();
        for (Entry<Object, Object> entry : policy.entrySet()) {
            jsonPolicy.put(entry.getKey(), entry.getValue());
        }

        ClientConfiguration clientConfig = createClientConfigration();

        try {
            // SecurityTokenServiceClientの設定
            AWSSecurityTokenServiceClient sts = new AWSSecurityTokenServiceClient(
                    new BasicAWSCredentials(this.accessKeyId, SecretAccessKey()), clientConfig);

            // GetFederationToken
            GetFederationTokenRequest req = new GetFederationTokenRequest();
            req.setName(name);
            req.setPolicy(jsonPolicy.toJSONString());
            if (durationSeconds != null) {
                req.setDurationSeconds(durationSeconds);
            }
            GetFederationTokenResult res = sts.getFederationToken(req);
            // FederationToken情報をJSON形式で取得する
            NativeObject federationTokenJson = createJsonResponse(res);

            return federationTokenJson;
        } catch (IllegalArgumentException e) {
            this.getLogger().info(e.getMessage(), e);
            throw ExtensionErrorConstructor.construct(e.toString());
        } catch (AmazonServiceException e) {
            this.getLogger().info(e.getMessage(), e);
            throw ExtensionErrorConstructor.construct(e.toString());
        } catch (AmazonClientException e) {
            this.getLogger().info(e.getMessage(), e);
            throw ExtensionErrorConstructor.construct(e.toString());
        } catch (ParseException e) {
            // レスポンスの整形に失敗した場合
            this.getLogger().error("Failed to create federation token response." + e.getMessage(), e);
            throw ExtensionErrorConstructor.construct(e.toString());
        }
    }

    private ClientConfiguration createClientConfigration() {
        ClientConfiguration clientConfig = new ClientConfiguration();
        clientConfig.setProxyHost(ProxyHost());
        clientConfig.setProxyPort(ProxyPort());
        clientConfig.setProxyUsername(ProxyUser());
        clientConfig.setProxyPassword(ProxyPassword());
        return clientConfig;
    }

    /**
     * SessionToken用のJSON形式のレスポンスを作成する.
     * @param res
     * @return JSONObject SessionToken情報(JSON形式)
     * @throws ParseException レスポンスの作成に失敗
     */
    @SuppressWarnings("unchecked")
    private NativeObject createJsonResponse(GetSessionTokenResult res) throws ParseException {
        Credentials credentials = res.getCredentials();

        JSONObject credentialsJson = new JSONObject();
        credentialsJson.put("AccessKeyId", credentials.getAccessKeyId());
        credentialsJson.put("SecretAccessKey", credentials.getSecretAccessKey());
        credentialsJson.put("SessionToken", credentials.getSessionToken());
        credentialsJson.put("Expiration", credentials.getExpiration().getTime());

        JSONObject sessionTokenJson = new JSONObject();
        sessionTokenJson.put("Credentials", credentialsJson);

        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        return (NativeObject) p.parseValue(sessionTokenJson.toJSONString());
    }

    /**
     * FederationToken用のJSON形式のレスポンスを作成する.
     * @param res
     * @return JSONObject FederationToken情報(JSON形式)
     * @throws ParseException レスポンスの作成に失敗
     */
    @SuppressWarnings("unchecked")
    private NativeObject createJsonResponse(GetFederationTokenResult res) throws ParseException {
        Credentials credentials = res.getCredentials();
        FederatedUser federatedUser = res.getFederatedUser();
        Integer packedPolicySize = res.getPackedPolicySize();

        JSONObject credentialsJson = new JSONObject();
        credentialsJson.put("AccessKeyId", credentials.getAccessKeyId());
        credentialsJson.put("SecretAccessKey", credentials.getSecretAccessKey());
        credentialsJson.put("SessionToken", credentials.getSessionToken());
        credentialsJson.put("Expiration", credentials.getExpiration().getTime());
        JSONObject federatedUserJson = new JSONObject();
        federatedUserJson.put("Arn", federatedUser.getArn());
        federatedUserJson.put("FederatedUserId", federatedUser.getFederatedUserId());

        JSONObject sessionTokenJson = new JSONObject();
        sessionTokenJson.put("Credentials", credentialsJson);
        sessionTokenJson.put("FederatedUser", federatedUserJson);
        sessionTokenJson.put("PackedPolicySize", packedPolicySize);

        JsonParser p = new JsonParser(Context.enter(), Context.enter().initStandardObjects());
        return (NativeObject) p.parseValue(sessionTokenJson.toJSONString());
    }

}
