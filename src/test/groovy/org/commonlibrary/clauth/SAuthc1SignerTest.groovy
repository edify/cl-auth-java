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

/**
 * Created by diugalde on 02/09/16.
 */

import org.junit.Before
import org.junit.runners.JUnit4
import org.junit.runner.RunWith
import junit.framework.TestCase
import org.junit.Test

import org.commonlibrary.clauth.model.ApiKeyCredentials


@RunWith(JUnit4.class)
class SAuthc1SignerTest extends TestCase {

    private def sAuthc1Signer = new SAuthc1Signer()

    private def headers, date, method, body, credentials, nonce

    @Before
    void initRequestData() {
        headers = new HashMap()
        def calendar = new GregorianCalendar(2013, 6, 1, 0, 0, 0, 0)
        date = calendar.getTime()
        method = 'get'
        body = ''
        credentials = new ApiKeyCredentials('MyId', 'Shush!')
        nonce = 'a43a9d25-ab06-421e-8605-33fd1e760825'
    }

    @Test
    void TestSAuthc1WithoutQueryParams() throws Exception {
        def requestURL = 'https://api.stormpath.com/v1/'

        def authHeader = sAuthc1Signer.sign(headers, method, requestURL, body, date, credentials, nonce)

        def expHeader = 'SAuthc1 sauthc1Id=MyId/20130701/a43a9d25-ab06-421e-8605-33fd1e760825/sauthc1_request, ' +
                        'sauthc1SignedHeaders=host;x-stormpath-date, ' +
                        'sauthc1Signature=990a95aabbcbeb53e48fb721f73b75bd3ae025a2e86ad359d08558e1bbb9411c'

        assertEquals(authHeader, expHeader);
    }

    @Test
    void TestSAuthc1WithMultipleQueryParams() throws Exception {
        def requestURL = 'https://api.stormpath.com/v1/applications/77JnfFiREjdfQH0SObMfjI/groups?q=group&limit=25&offset=25'

        def authHeader = sAuthc1Signer.sign(headers, method, requestURL, body, date, credentials, nonce)

        def expHeader = 'SAuthc1 sauthc1Id=MyId/20130701/a43a9d25-ab06-421e-8605-33fd1e760825/sauthc1_request, ' +
                        'sauthc1SignedHeaders=host;x-stormpath-date, ' +
                        'sauthc1Signature=e30a62c0d03ca6cb422e66039786865f3eb6269400941ede6226760553a832d3'

        assertEquals(authHeader, expHeader);
    }
}


