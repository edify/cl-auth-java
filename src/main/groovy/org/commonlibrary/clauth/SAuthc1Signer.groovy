/*
 * Copyright 2016 Edify Software Consulting.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


 package org.commonlibrary.clauth

/*
 * Created by diugalde on 01/09/16.
 *
 * This groovy version of the SAuthc1 algorithm is based on the Stormpath Java SDK.
 */

import java.text.SimpleDateFormat

import org.commonlibrary.clauth.support.SAuthc1Exception
import org.commonlibrary.clauth.utils.Utils

class SAuthc1Signer {

    public static final def HOST_HEADER = 'Host'
    public static final def STORMPATH_DATE_HEADER = 'X-Stormpath-Date'
    public static final def ID_TERMINATOR = 'sauthc1_request'
    public static final def ALGORITHM = 'HMAC-SHA-256'
    public static final def AUTHORIZATION_HEADER = 'Authorization'
    public static final def AUTHENTICATION_SCHEME = 'SAuthc1'
    public static final def SAUTHC1_ID = 'sauthc1Id'
    public static final def SAUTHC1_SIGNED_HEADERS = 'sauthc1SignedHeaders'
    public static final def SAUTHC1_SIGNATURE = 'sauthc1Signature'
    public static final def DATE_FORMAT = 'yyyyMMdd'
    public static final def TIMESTAMP_FORMAT = "yyyyMMdd'T'HHmmss'Z'"

    private static final def NL = '\n'

    /**
     * Generates an authorization header using the SAuthc1 algorithm for the signature.
     * Note: The received headers Map will be modified. This function adds Host and date headers.
     *
     * @param headers - Map
     * @param method - String
     * @param requestURL - String
     * @param body - String
     * @param date - Date
     * @param credentials - ApiKeyCredentials
     * @param nonce - String (should be random)
     * @returns String (Authorization header ready to be sent).
     */
    def sign(headers, method, requestURL, body, date, credentials, nonce) throws SAuthc1Exception {
        try {
            // Create required date objects.
            def dateFormat = new SimpleDateFormat(DATE_FORMAT)
            def timestampFormat = new SimpleDateFormat(TIMESTAMP_FORMAT)
            def timestamp = timestampFormat.format(date)
            def dateStamp = dateFormat.format(date)

            // Parse url string to obtain URI components.
            def uriObject = URI.create(requestURL)

            // Retrieve host from url.
            def hostHeader = uriObject.getHost()
            def port = uriObject.getPort()
            if(port && port > 0) {
                hostHeader += ":${port}"
            }

            // Set new headers.
            headers.put(HOST_HEADER, hostHeader)
            headers.put(STORMPATH_DATE_HEADER, timestamp)

            // Build canonical request.
            def canonicalResourcePath = canonicalizeResourcePath(uriObject.getPath())
            def canonicalQueryString = canonicalizeQueryString(Utils.getQueryParamsMap(uriObject.getQuery()))
            def canonicalHeadersString = canonicalizeHeadersString(headers)
            def signedHeadersString = getSignedHeadersString(headers)
            def requestPayloadHashHex = Utils.toHex(Utils.hash(body))

            def canonicalRequest = "${method.toUpperCase()}\n${canonicalResourcePath}\n${canonicalQueryString}\n" +
                    "${canonicalHeadersString}\n${signedHeadersString}\n${requestPayloadHashHex}"

            // Create string to sign.
            def id = "${credentials.apiKeyId}/${dateStamp}/${nonce}/${ID_TERMINATOR}"
            def canonicalRequestHashHex = Utils.toHex(Utils.hash(canonicalRequest))
            def stringToSign = "${ALGORITHM}\n${timestamp}\n${id}\n${canonicalRequestHashHex}"

            // Generate final signature.
            def kSecret = Utils.toUtf8Bytes("${AUTHENTICATION_SCHEME}${credentials.apiSecretKey}")
            def kDate = Utils.signSHA256(dateStamp, kSecret)
            def kNonce = Utils.signSHA256(nonce, kDate)
            def kSigning = Utils.signSHA256(ID_TERMINATOR, kNonce)
            def signature = Utils.toHex(Utils.signSHA256(stringToSign, kSigning))

            def authHeader = "${AUTHENTICATION_SCHEME} ${SAUTHC1_ID}=${id}, ${SAUTHC1_SIGNED_HEADERS}=${signedHeadersString}" +
                    ", ${SAUTHC1_SIGNATURE}=${signature}"

            headers.put(AUTHORIZATION_HEADER, authHeader)

            return authHeader
        } catch(Exception e) {
            throw new SAuthc1Exception(e.getMessage(), e.getCause())
        }
    }

    /**
     * Creates a string containing all query params and their values properly encoded.
     * The query params are sorted first.
     * @example param1=value1&param2=value2
     *
     * @param queryParams - Map.
     * @returns String
     */
    private def canonicalizeQueryString(queryMap) {
        def queryParamsNames = queryMap.keySet() as ArrayList
        Collections.sort(queryParamsNames, String.CASE_INSENSITIVE_ORDER)

        def encodedName, paramValue, encodedValue
        def queryStringList = queryParamsNames.collect() {
            encodedName = Utils.encodeURL(it, false, true)
            paramValue = queryMap.get(it)
            encodedValue = Utils.encodeURL(paramValue, false, true)
            return "${encodedName}=${encodedValue}"
        }
        return queryStringList.join('&')
    }

    /**
     * Encodes the received path.
     *
     * @param path - url String.
     * @return String (encoded path).
     */
    private def canonicalizeResourcePath(resourcePath) { (!resourcePath || resourcePath.length() == 0) ? '/' : Utils.encodeURL(resourcePath, true, true) }

    /**
     * Creates a string containing all header names and their values.
     * The headers are sorted by name first.
     * @example header1:value1
     *           header2:value2
     *
     * @param headers - Map.
     * @returns String
     */
    private def canonicalizeHeadersString(headersMap) {
        def sortedHeaders = headersMap.keySet() as ArrayList
        Collections.sort(sortedHeaders, String.CASE_INSENSITIVE_ORDER)

        def headerStringList = sortedHeaders.collect() { def header ->
            return "${header.toLowerCase()}:${headersMap.get(header)}"
        }
        return "${headerStringList.join('\n')}\n"
    }

    /**
     * Creates a string containing all header names separated by ; properly encoded.
     * The header names are sorted and lowercase.
     * @example host;x-stormpath-date
     *
     * @param headers - Map.
     * @return String
     */
    private def getSignedHeadersString(headersMap) {
        def sortedHeaders = headersMap.keySet() as ArrayList
        Collections.sort(sortedHeaders, String.CASE_INSENSITIVE_ORDER)

        def signedHeaderList = sortedHeaders.collect() { def header ->
            return "${header.toLowerCase()}"
        }
        return "${signedHeaderList.join(';')}"
    }
}
