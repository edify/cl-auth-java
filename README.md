# cl-auth-java

Common Library Authentication Package for Java. This jar can be used to generate authentication headers using the Stormpath"s SAuthc1 algorithm.

---

## Usage

```java

    import org.commonlibrary.clauth.SAuthc1Signer;
    import org.commonlibrary.clauth.model.ApiKeyCredentials;


    Map<String, String> headers = new HashMap();
    Calendar calendar = new GregorianCalendar(2013, 6, 1, 0, 0, 0, 0);
    Date date = calendar.getTime();
    String method = "get";
    String body = "";
    ApiKeyCredentials credentials = new ApiKeyCredentials("MyId", "Shush!");
    String nonce = "a43a9d25-ab06-421e-8605-33fd1e760825";
    String requestURL = "https://api.stormpath.com/v1/"

    SAuthc1Signer signer = new SAuthc1Signer();

    String authHeader = sAuthc1Signer.sign(headers, method, requestURL, body, date, credentials, nonce);

    System.out.println(authHeader);

    /*
        Result:
        "SAuthc1 sauthc1Id=MyId/20130701/a43a9d25-ab06-421e-8605-33fd1e760825/sauthc1_request, " +
        "sauthc1SignedHeaders=host;x-stormpath-date, " +
        "sauthc1Signature=990a95aabbcbeb53e48fb721f73b75bd3ae025a2e86ad359d08558e1bbb9411c"
    */

```
