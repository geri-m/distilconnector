package at.madlmayr;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestDistilCall {

    /*
        This information will be fetched from ENV variables in order not to check them in by accident for now.

        Edit your profile file in order to have the parameters as environment variables. As we are using this in a container
        later, the ENV variables are the way to go.

        nano ~/.bash_profile

        export analysis_host="bonproxy";
        export analysis_host_port=80;
        export api_key_id="debug-id";
        export api_secret_key="password";
     */


    @Test
    public void connectToRedisAndRWData() throws Exception {
        String host = System.getenv("analysis_host");
        int port = Integer.parseInt(System.getenv("analysis_host_port"));
        String keyId = System.getenv("api_key_id");
        String secretKey = System.getenv("api_secret_key");

        // Sample HTTP Request
        // ATTENTION: Line feed is \r\n as stated here: https://www.w3.org/Protocols/rfc2616/rfc2616-sec2.html#sec2.2
        String httpRequest = "GET / HTTP/1.1\r\n" +
                "Host: aws-smoketest-staging.distil.ninja\r\n" +
                "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:63.0) Gecko/20100101 Firefox/63.0\r\n" +
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
                "Accept-Language: en-US,en;q=0.5\r\n" +
                "Accept-Encoding: gzip, deflate\r\n" +
                "\r\n";

        byte[] base64request = Base64.getEncoder().encode(httpRequest.getBytes());

        // Check that the Base64 is okay
        assertEquals(new String(base64request), "R0VUIC8gSFRUUC8xLjENCkhvc3Q6IGF3cy1zbW9rZXRlc3Qtc3RhZ2luZy5kaXN0aWwubmluamENClVzZXItQWdlbnQ6IE1vemlsbGEvNS4wIChNYWNpbnRvc2g7IEludGVsIE1hYyBPUyBYIDEwLjEzOyBydjo2My4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzYzLjANCkFjY2VwdDogdGV4dC9odG1sLGFwcGxpY2F0aW9uL3hodG1sK3htbCxhcHBsaWNhdGlvbi94bWw7cT0wLjksKi8qO3E9MC44DQpBY2NlcHQtTGFuZ3VhZ2U6IGVuLVVTLGVuO3E9MC41DQpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAsIGRlZmxhdGUNCg0K");

        String json = String.format("{\n" +
                "  \"client_ip\": \"10.20.30.40\",\n" +
                "  \"raw_request\": \"%s\"\n" +
                "}", base64request);


        URL url = new URL(host + ":" + port + "/v6/analysis");

        // we use the basic HttpURLConnection as the next step, in order not to add additional libs/overhead for now.
        HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
        httpURLConnection.setRequestMethod("POST");

        String userCredentials = keyId+ ":" + secretKey;
        String basicAuth = "Basic " + new String(Base64.getEncoder().encode(userCredentials.getBytes()));

        httpURLConnection.setRequestProperty("Authorization", basicAuth);
        httpURLConnection.setRequestMethod("POST");
        httpURLConnection.setRequestProperty("Content-Type", "application/json");
        httpURLConnection.setRequestProperty("Content-Length", "" + json.getBytes().length);

        byte[] outputInBytes = json.getBytes(StandardCharsets.UTF_8);
        OutputStream os = httpURLConnection.getOutputStream();
        os.write(outputInBytes);
        os.close();

        BufferedReader br;
        if (200 <= httpURLConnection.getResponseCode() && httpURLConnection.getResponseCode() <= 299) {
            br = new BufferedReader(new InputStreamReader(httpURLConnection.getInputStream()));
        } else {
            br = new BufferedReader(new InputStreamReader(httpURLConnection.getErrorStream()));
        }

        String responseBody = br.lines().collect(Collectors.joining());

        System.out.println(responseBody);

    }

}
