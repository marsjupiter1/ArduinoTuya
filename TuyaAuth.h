#include <WiFi.h>
#include <HTTPClient.h>
#include <stdio.h>
#include <Arduino.h>
#include <vector>
#include <SHA256.h>
#include "mbedtls/md.h"
#include <ArduinoJson.h>
#include "time.h"

#define SHA256_HASH_SIZE 32


class TuyaAuth {

    time_t lastauth = 0;  
    time_t expires_in;
    static void auth(void *parameter) {

      TuyaAuth *This = (TuyaAuth *)parameter;

      HTTPClient http;
     
      for (;;) {

        char ts[14];
        time_t t = time(NULL);
        // time will be offset from 0 until we have synced
        if (t < 99999999) {
          Serial.print("*");
          delay(5000);
          continue;
        }
        if (This->lastauth == 0 || t >= This->lastauth + This->expires_in) {
          char url[200];
          char ts[14];
          TuyaAuth::timestamp(ts);
          char sign[400];
          const char *QUERY = "/v1.0/token?grant_type=1";
          sprintf(url, "%s%s", This->host, QUERY );
          This->getRequestAuth(ts, This->client_id, This->secret_key, QUERY, "GET", "", sign);

          http.begin(url);

          http.addHeader(String("t") , String(ts));
          http.addHeader(String("sign_method"), String("HMAC-SHA256"));
          http.addHeader(String("client_id"), String(This->client_id));
          http.addHeader(String("sign") , String(sign));
          int err = http.GET();


          String body = http.getString();

          if (err == 200) {
            DynamicJsonDocument root(5000);

            DeserializationError err = deserializeJson(root, body.c_str());

            if (err) {
              Serial.println("auth error");
              Serial.println(body);
            } else {
              if (root.containsKey("result")) {
                Serial.println(body);
                Serial.println("Authorised");
                strcpy(This->tuya_token, root["result"]["access_token"]);
                This->lastauth = t;
                This->expires_in = root["result"]["expire_time"];
              } else {
                Serial.println("missing result");
                Serial.println(body);
              }
            }
          } else {
            Serial.println("Failed to connect");
            Serial.println(err);
            Serial.println(body);
          }
        }

        delay(1000);
      }
    }

    String join(std::vector<String> &v, String delimiter) {
      static String j;
      for (int i = 0; i < v.size(); i++)
      {
        j +=   v[i] + delimiter;

      }
      return j.substring(0, j.length() - 1);
    }
    std::vector<String> split (String s, String delimiter) {
      size_t pos_start = 0, pos_end, delim_len = delimiter.length();
      String token;
      std::vector<String> res;

      while ((pos_end = s.indexOf(delimiter, pos_start)) != -1) {
        token = s.substring(pos_start, pos_end - pos_start);
        pos_start = pos_end + delim_len;
        res.push_back (token);
      }

      res.push_back (s.substring(pos_start));
      return res;
    }
  public:
    TaskHandle_t Task;
    char tuya_token[100];
    char client_id[33];
    char secret_key[33];
    char host[100];

    bool isConnected(){
        return this->lastauth>0;
    }

    TuyaAuth(const char *h, const char *c, const char *secret) {

      strcpy(client_id, c);
      strcpy(secret_key, secret);
      strcpy(host, h);
      tuya_token[0] = '\0';
      xTaskCreatePinnedToCore(
        this->auth,   /* Task function. */
        "Auth",     /* name of task. */
        10000,       /* Stack size of task */
        this,        /* parameter of the task */
        1,           /* priority of the task */
        &Task,      /* Task handle to keep track of created task */
        0);          /* pin task to core 0 */

    }

    void  hmac(const char *key, const char *payload, char *out_str) {
      uint8_t out[SHA256_HASH_SIZE];

      mbedtls_md_context_t ctx;
      mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

      const size_t payloadLength = strlen(payload);
      const size_t keyLength = strlen(key);

      mbedtls_md_init(&ctx);
      mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
      mbedtls_md_hmac_starts(&ctx, (const unsigned char *) key, keyLength);
      mbedtls_md_hmac_update(&ctx, (const unsigned char *) payload, payloadLength);
      mbedtls_md_hmac_finish(&ctx, out);
      mbedtls_md_free(&ctx);

      for (int i = 0; i < sizeof(out); i++) {
        snprintf(&out_str[i * 2], 3, "%02x", out[i]);
        out_str[i * 2] = toupper(out_str[i * 2]);
        out_str[i * 2 + 1] = toupper(out_str[i * 2 + 1]);
      }
      out_str[2 * SHA256_HASH_SIZE] = '\0';

    }

    void _sha256(String key, char *out) {
      SHA256 sha;
      char buffer[SHA256_HASH_SIZE + 1];
      sha.update((void *)key.c_str(), (size_t)key.length());
      sha.finalize(buffer, SHA256_HASH_SIZE);
      for (int i = 0; i < SHA256_HASH_SIZE; i++) {
        snprintf(&out[i * 2], 3, "%02x", buffer[i]);

      }
      out[2 * SHA256_HASH_SIZE] = '\0';
    }


    static void timestamp(char *out) {
      time_t now = time(NULL);
      // tuya wants 13 digits, but doesn't care about the final 3 just so long as the time looks currentish
      sprintf(out, "%d999", now);

    }


    //https://developer.tuya.com/en/docs/iot/singnature?id=Ka43a5mtx1gsc
    void getRequestSign( const char *t, const char *accessKey, const char *clientKey,  const char *secretKey, const char *url, const char *method,  const char *body, char *out) {

      std::vector<String> host_params = split (String(url), String("?"));

      String request = host_params[0];
      if (host_params.size() > 1) {
        std::vector<String> params = split(host_params[1], "&");
        struct {
          bool operator()(String a, String b) const {
            return a < b;
          }
        } customLess;
        std::sort(params.begin(), params.end(), customLess);
        request += String("?") + join(params, String("&"));
      }

      char contentHash[SHA256_HASH_SIZE * 2 + 1];
      _sha256(body, contentHash);
      String StringToSign = String(method) + String("\n") + String(contentHash) + String("\n") + String("\n") + request;
      String signStr = String(clientKey) + String(accessKey) + String(t) + StringToSign;

      hmac(secretKey, signStr.c_str(), out);

    }

    //https://developer.tuya.com/en/docs/iot/singnature?id=Ka43a5mtx1gsc
    void getRequestAuth( char *t, const char *clientKey, const char *secretKey, const char *url, const char *method, const  char *body, char *out) {
      std::vector<String> host_params = split (String(url), String("?"));
      String request = host_params[0];
      String query = host_params[1];

      // soring nothing here, as there is only one param currently, but things may change
      std::vector<String> params = split(host_params[1], "&");
      struct {
        bool operator()(String a, String b) const {
          return a < b;
        }
      } customLess;
      std::sort(params.begin(), params.end(), customLess);
      request += String(" ? ") + join(params, String("&"));

      char contentHash[SHA256_HASH_SIZE * 2 + 1];
      _sha256("", contentHash);

      String StringToSign = String(method) + String("\n") + String(contentHash) + String("\n") + String("\n") + url;
      String signStr = String(clientKey) + String(t) + StringToSign;

      hmac(secretKey, signStr.c_str(), out);

    }

    bool TGetSwitch(const char *device_id, String &out) {

      // are we waiting on authorisation?
      if (strlen(tuya_token) == 0) {
        Serial.print("@");
        return false;
      }

      char buffer[1200];
      char command[200];
      sprintf(command, "/v1.0/iot-03/devices/%s/functions", device_id);
      if (TGet(device_id, command, buffer)) {
        Serial.println(buffer);
        DynamicJsonDocument root(3000);

        DeserializationError err = deserializeJson(root, buffer);

        if (err) {

          Serial.println(out);
          Serial.println(err.c_str());
        } else {
          Serial.println(out);

          if (root.containsKey("result")) {

            String s = root["result"]["functions"][0]["code"];
            out =s;

            return true;
          } else {
            
            Serial.println(out);
          }
        }
      }
      return false;
    }

    bool TGetOnStatus(const char *device_id, const char *switch_code, bool &on) {

      // are we waiting on authorisation?
      if (strlen(tuya_token) == 0) {
        Serial.print("@");
        return false;
      }

      char buffer[600];
      char command[100];
      sprintf(command, "/v1.0/iot-03/devices/%s/status", device_id);
      if (TGet(device_id, command, buffer)) {
        Serial.println(buffer);
        DynamicJsonDocument root(300);

        DeserializationError err = deserializeJson(root, buffer);

        if (err) {

         
          Serial.println(err.c_str());
        } else {

          if (root.containsKey("result")) {

           on = root["result"]["code"][switch_code];
           

            return true;
          } 
        }
      }
      return false;
    }

    bool TGet(const char *device_id, const char *command, char *out) {

      HTTPClient http;
      char query[100];
      char url[200];
      char ts[14];
      timestamp(ts);
      char sign[200];

      if (strlen(tuya_token) == 0) {
        Serial.print("@");
        return false;
      }

      TuyaAuth::timestamp(ts);
      sprintf(url, "%s%s", this->host, command );

      getRequestSign(ts, tuya_token, client_id, secret_key, command, "GET", "", sign);
      http.begin(url);
      http.addHeader(String("t") , String(ts));
      http.addHeader(String("sign_method"), String("HMAC-SHA256"));
      http.addHeader(String("client_id"), String(client_id));
      http.addHeader(String("mode"), String("cors"));

      http.addHeader(String("access_token"), String(tuya_token));
      http.addHeader(String("sign") , String(sign));

      http.addHeader(String("Content-Type"), String("application/json"));

      int err = http.GET();

      String body = http.getString();
      Serial.println(body);
      if (err == 200) {
        strcpy(out, body.c_str());
        return true;
      } else {
        Serial.println("Failed to connect");
        Serial.println(err);
      }

      return false;
    }

    bool TCommand(const char *device_id, const char *command) {

      HTTPClient http;
      char query[100];
      char url[200];
      char ts[14];
      timestamp(ts);
      char sign[200];

      if (strlen(tuya_token) == 0) {
        Serial.print("@");
        return false;
      }

      TuyaAuth::timestamp(ts);
      sprintf(query, "/v1.0/iot-03/devices/%s/commands",  device_id);
      sprintf(url, "%s%s", this->host, query );

      getRequestSign(ts, tuya_token, client_id, secret_key, query, "POST", command, sign);
      http.begin(url);
      Serial.println(url);
      Serial.println(command);

      http.addHeader(String("t") , String(ts));
      http.addHeader(String("sign_method"), String("HMAC-SHA256"));
      http.addHeader(String("client_id"), String(client_id));
      http.addHeader(String("mode"), String("cors"));

      http.addHeader(String("access_token"), String(tuya_token));
      http.addHeader(String("sign") , String(sign));

      http.addHeader(String("Content-Type"), String("application/json"));

      int err = http.POST(command);
      String body = http.getString();
      Serial.println(body);
      if (err == 200) {
        DynamicJsonDocument root(5000);

        DeserializationError err = deserializeJson(root, body.c_str());

        if (err) {
          Serial.println("command error");
        } else {
          if (root.containsKey("result")) {

            return true;
          } else {
            Serial.println("missing result");
          }
        }
      } else {
        Serial.println("Failed to connect");
        Serial.println(err);
      }

      return false;
    }

};


