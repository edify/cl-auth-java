package org.commonlibrary.clauth.utils

/**
 * Created by diugalde on 02/09/16.
 */

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest
import org.apache.commons.codec.binary.Base64

class Utils {

    public static final def MAC_ALGORITHM = 'HmacSHA256'
    public static final def DEFAULT_ENCODING = 'UTF-8'

    /**
     * Converts string to UTF-8 encoded byte array.
     *
     * @param s
     * @return byte array encoded with UTF-8
     */
    static def toUtf8Bytes(String s) {
        if(!s) {
            return null
        }
        try {
            return s.getBytes(DEFAULT_ENCODING)
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException('Unable to UTF-8 encode!', e)
        }
    }

    /**
     * Converts byte data to a Hex-encoded string.
     *
     * @param data data to hex encode.
     * @return hex-encoded string.
     */
    static def toHex(data) {
        def sb = new StringBuilder(data.length * 2)
        for(def i = 0; i < data.length; i++) {
            def hex = Integer.toHexString(data[i])
            if (hex.length() == 1) {
                // Append leading zero.
                sb.append('0')
            } else if (hex.length() == 8) {
                // Remove ff prefix from negative numbers.
                hex = hex.substring(6)
            }
            sb.append(hex)
        }
        return sb.toString().toLowerCase(Locale.getDefault())
    }

    /**
     * Hashes the string contents (assumed to be UTF-8) using the SHA-256
     * algorithm.
     *
     * @param text The string to hash.
     * @return The hashed bytes from the specified string.
     */
    static def hash(text){
        def md = MessageDigest.getInstance('SHA-256')
        md.update(text.getBytes(DEFAULT_ENCODING))
        return md.digest()
    }

    static def signSHA256(stringData, key) {
        def mac = Mac.getInstance(MAC_ALGORITHM)
        mac.init(new SecretKeySpec(key, MAC_ALGORITHM))
        return mac.doFinal(stringData.getBytes(DEFAULT_ENCODING))
    }

    /**
     * Encodes the string value doing the following replacements:
                                                                 + to %20
                                                                 * to %2A
                                                                 %7E back to ~
                                                                 %2F back to /
     *
     * @param value - string to encode.
     * @param isPath - boolean.
     * @param isCanonical - boolean.
     * @return string (encoded value).
     */
    static def encodeURL(value, isPath, isCanonical) {
        if (!value || value == '') {
            return ''
        }

        def encoded = URLEncoder.encode(value, 'UTF-8')

        if (isCanonical) {
            encoded = encoded.replace("+", "%20")
                    .replace("*", "%2A")
                    .replace("%7E", "~")

            if (isPath) {
                encoded = encoded.replace("%2F", "/")
            }
        }

        return encoded
    }

    /**
     * Creates a map from a query params string.
     * @example Converts param1=value1&param2=value2 to a map like {param1: value1, param2: value2}
     *
     * @param queryStr - string
     * @return map
     */
    static def getQueryParamsMap(queryStr) {
        def map = [:] as HashMap
        if (!queryStr) {
            return map
        }
        def paramSplit
        def queryParams = queryStr.split('&')
        queryParams.each() { def param ->
            paramSplit = param.split('=')
            map.put(paramSplit[0], paramSplit[1])
        }
        return map
    }

    /**
     * Decrypts an encrypted secret api key using PBKDF2 and AES algorithms.
     *
     * @param encryptedString
     * @return decryptedString
     */
    static def decrypt(encryptedString, decryptionPassphrase) {
        try {
            def salt = 'RwKwsDB3qUo6RD8YwHLoy+UkHTcgitWGLriAoGBXt30='
            def iterations = 1024
            def keyLength = 32

            PBEKeySpec spec = new PBEKeySpec(decryptionPassphrase.toCharArray(), Base64.decodeBase64(salt), iterations, keyLength * 8)
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")

            def hashedKey = skf.generateSecret(spec).getEncoded()
            def iv = new IvParameterSpec(Arrays.copyOfRange(hashedKey, 0, 16))
            def slicedHashedKey = Arrays.copyOfRange(hashedKey, 16, hashedKey.length)

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec key = new SecretKeySpec(slicedHashedKey, "AES")
            cipher.init(Cipher.DECRYPT_MODE, key, iv)

            return new String(cipher.doFinal(Base64.decodeBase64(encryptedString)))
        } catch(Exception e) {
            throw e
        }
    }
}
