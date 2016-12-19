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


 package org.commonlibrary.clauth.services.impl

import com.lambdaworks.redis.RedisClient
import org.commonlibrary.clauth.services.ApiKeyService
import org.commonlibrary.clauth.utils.Utils


/**
 * Created by diugalde on 13/09/16.
 */
class ApiKeyServiceImpl implements ApiKeyService {

    def redisConnection

    def decryptionPassphrase

    ApiKeyServiceImpl() {
        def env = System.getenv()

        def redisHost = env['CL_REDIS_HOST'] ?: 'localhost'
        def redisPort = env['CL_REDIS_PORT'] ?: 6379
        this.redisConnection = RedisClient.create("redis://${redisHost}").connect()
        this.decryptionPassphrase = env['CL_AUTH_PASSPHRASE'] ?: 'passphrase'
    }

    ApiKeyServiceImpl(redisConnection, decryptionPassphrase) {
        this.redisConnection = redisConnection
        this.decryptionPassphrase = decryptionPassphrase
    }

    /**
     * Retrieves and decrypts secret key from redis.
     *
     * @param apiKeyId
     * @return
     */
    def getApiSecretKey(apiKeyId) {
        try {
            def secret = redisConnection.sync().hget(apiKeyId, 'apiSecretKey')
            if(!secret) {
                throw new Exception('The provided apiKeyId does not exist', null)
            }

            def decryptedSecret = Utils.decrypt(secret, decryptionPassphrase)
            return decryptedSecret
        }catch(Exception e) {
            throw e
        }
    }
}
