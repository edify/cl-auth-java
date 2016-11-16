package org.commonlibrary.clauth.model

/**
 * Created by diugalde on 01/09/16.
 */

class ApiKeyCredentials {

    def apiKeyId
    def apiSecretKey

    ApiKeyCredentials(apiKeyId, apiSecretKey) {
        this.apiKeyId = apiKeyId
        this.apiSecretKey = apiSecretKey
    }
}
