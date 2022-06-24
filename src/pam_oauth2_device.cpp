#include "pam_oauth2_device.h"
// std
#include <chrono>
#include <fstream>
#include <sstream>
#include <regex>
#include <thread>
// curl
#include <curl/curl.h>
// security
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <syslog.h>
// json
#include "json/single_include/nlohmann/json.hpp"
// QRCode
#include "QR-Code-generator/cpp/qrcodegen.hpp"

void load_config(const char *path, Config *config)
{
    ifstream config_fstream(path);
    nlohmann::json json;
    config_fstream >> json;
    // oauth
    auto oauth = json.at("oauth");
    config->client_id = oauth.at("client").at("id").get<string>();
    config->client_secret = oauth.at("client").at("secret").get<string>();
    config->scope = oauth.at("scope").get<string>();
    config->device_code_url = oauth.at("device_code_url").get<std::string>();
    config->access_token_url = oauth.at("access_token_url").get<std::string>();
    config->user_info_url = oauth.at("user_info_url").get<std::string>();
    config->username_attribute = oauth.at("username_attribute").get<std::string>();
    config->name_attribute = oauth.at("name_attribute").get<std::string>();
    config->sub_attribute = oauth.at("sub_attribute").get<std::string>();
    config->require_mfa = oauth.contains("require_mfa") ? oauth.at("require_mfa").get<bool>() : false;
    // qr code
    auto qr = json.at("qr");
    config->qr_error_correction_level = (qr.contains("error_correction_level")) ? qr.at("error_correction_level").get<int>() : 0;
    config->qr_show = (qr.contains("show")) ? qr.at("show").get<bool>() : true;
    // users
    if (json.find("users") != json.end())
    {
        for (auto &element : json["users"].items())
        {
            for (auto &local_user : element.value())
            {
                if (config->users.find(element.key()) == config->users.end())
                {
                    set<string> userset;
                    userset.insert((string)local_user);
                    config->users[element.key()] = userset;
                }
                else
                {
                    config->users[element.key()].insert((string)local_user);
                }
            }
        }
    }
}

/* The OAuth Start */
static size_t WriteCallback(void *contents, size_t size, size_t nmb, void *up)
{
    ((string *)up)->append(reinterpret_cast<char *>(contents), size * nmb);
    return size * nmb;
}

void post_device_code(const Config &config, DeviceCode *code)
{
    CURL *curl = curl_easy_init();
    if (!curl)
    {
        syslog(LOG_ERR, "post_device_code: curl initialization failed");
        throw NetworkError();
    }
    // set header json format
    curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    // set params
    string params;
    params += "client_id=" + config.client_id;
    params += "&scope=" + config.scope;
    if (config.require_mfa)
    {
        params += "&acr_values=";
        params += "https://refeds.org/profile/mfa ";
        params += "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
    }
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params.c_str());
    curl_easy_setopt(curl, CURLOPT_URL, config.device_code_url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERNAME, config.client_id.c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, config.client_secret.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    // set read buffer
    string readBuffer;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    CURLcode result = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (result != CURLE_OK)
    {
        syslog(LOG_ERR, "post_device_code: curl failed with result code: %d", result);
        throw NetworkError();
    }
    try
    {
        auto data = nlohmann::json::parse(readBuffer);
        code->user_code = data.at("user_code");
        code->device_code = data.at("device_code");
        code->verification_uri = data.at("verification_uri");
        if (data.find("verification_uri_complete") != data.end())
        {
            code->verification_uri_complete = data.at("verification_uri_complete");
        }
    }
    catch (nlohmann::json::exception &e)
    {
        syslog(LOG_ERR, "post_device_code: json parse failed with error: %s", e.what());
        throw ResponseError();
    }
}

void post_access_token(const Config &config, const DeviceCode &code, AccessToken *token)
{
    int timeout = 300, interval = 3;
    while (true)
    {
        timeout -= interval;
        if (timeout < 0)
        {
            syslog(LOG_ERR, "post_access_token: timeout %ds exceeded", timeout);
            throw TimeoutError();
        }
        // wait
        this_thread::sleep_for(chrono::seconds(interval));
        // continue
        CURL *curl = curl_easy_init();
        if (!curl)
        {
            syslog(LOG_ERR, "post_access_token: curl initialization failed");
            throw NetworkError();
        }
        // set header json format
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        // set params
        string params;
        params += "grant_type=urn:ietf:params:oauth:grant-type:device_code";
        params += "&client_id=" + config.client_id;
        params += "&device_code=" + code.device_code;
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params.c_str());
        curl_easy_setopt(curl, CURLOPT_URL, config.access_token_url.c_str());
        curl_easy_setopt(curl, CURLOPT_USERNAME, config.client_id.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD, config.client_secret.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        // set read buffer
        string readBuffer;
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        CURLcode result = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        if (result != CURLE_OK)
        {
            syslog(LOG_ERR, "post_access_token: curl failedw with result code: %d", result);
            throw NetworkError();
        }
        try
        {
            auto data = nlohmann::json::parse(readBuffer);
            if (data["error"].empty())
            {
                token->access_token = data.at("access_token");
                token->token_type = data.at("token_type");
                token->scope = data.at("scope");
                return;
            }
            else if (data["error"] == "authorization_pending")
            {
                // Do nothing
            }
            else if (data["error"] == "slow_down")
            {
                ++interval;
            }
            else
            {
                syslog(LOG_ERR, "poll_for_token: unknown response '%s'", (string(data["error"])).c_str());
                throw ResponseError();
            }
        }
        catch (nlohmann::json::exception &e)
        {
            syslog(LOG_ERR, "post_access_token: json parse failed with error: %s", e.what());
            throw ResponseError();
        }
    }
}

void get_user_info(const Config &config, const AccessToken &token, UserInfo *user_info)
{
    CURL *curl = curl_easy_init();
    if (!curl)
    {
        syslog(LOG_ERR, "get_user_info: curl initialization failed");
        throw NetworkError();
    }
    // set header json format
    curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");
    // set auth header
    string auth_header = "Authorization: Bearer " + token.access_token;
    headers = curl_slist_append(headers, auth_header.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, config.user_info_url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    // set read buffer
    string readBuffer;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    CURLcode result = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (result != CURLE_OK)
    {
        syslog(LOG_ERR, "get_user_info: curl failed with result code: %d", result);
        throw NetworkError();
    }
    try
    {
        auto data = nlohmann::json::parse(readBuffer);
        user_info->username = data.at(config.username_attribute);
        if (config.name_attribute.length() > 0 && data.find("name") != data.end())
        {
            user_info->name = data.at(config.name_attribute);
        }
        if (config.sub_attribute.length() > 0 && data.find("sub") != data.end())
        {
            user_info->sub = data.at(config.sub_attribute);
        }
        if (data.find("acr") != data.end())
        {
            user_info->acr = data.at("acr");
        }
        else
        {
            user_info->acr = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
        }
    }
    catch (nlohmann::json::exception &e)
    {
        syslog(LOG_ERR, "get_userinfo: json parse failed, error: %s", e.what());
        throw ResponseError();
    }
}

/* The OAuth End */

string getQR(const char *text, const int ecc = 0, const int border = 1)
{
    qrcodegen::QrCode::Ecc error_correction_level;
    switch (ecc)
    {
    case 1:
        error_correction_level = qrcodegen::QrCode::Ecc::MEDIUM;
        break;
    case 2:
        error_correction_level = qrcodegen::QrCode::Ecc::HIGH;
        break;
    default:
        error_correction_level = qrcodegen::QrCode::Ecc::LOW;
        break;
    }
    qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(text, error_correction_level);
    // trans to ASCII
    ostringstream oss;
    int size = qr.getSize();
    for (int j = -border; j < size + border; j += 2)
    {
        for (int i = -border; i < size + border; ++i)
        {
            int top = qr.getModule(i, j);
            int bottom = qr.getModule(i, j + 1);
            if (top && bottom)
            {
                oss << "\033[40;97m \033[0m";
            }
            else if (top && !bottom)
            {
                oss << "\033[40;97m\u2584\033[0m";
            }
            else if (!top && bottom)
            {
                oss << "\033[40;97m\u2580\033[0m";
            }
            else
            {
                oss << "\033[40;97m\u2588\033[0m";
            }
        }
        oss << std::endl;
    }
    return oss.str();
}

string make_prompt(const Config &config, const DeviceCode &code)
{
    bool complete_url = !code.verification_uri_complete.empty();
    string text = (complete_url ? code.verification_uri_complete : code.verification_uri);
    ostringstream prompt;
    prompt
        << "Authenticate at the identity provider using the following URL."
        << endl
        << endl;
    if (config.qr_show)
    {
        prompt
            << "Alternatively, to authenticate with a mobile device, scan the QR code."
            << endl
            << endl
            << getQR(text.c_str(), config.qr_error_correction_level)
            << endl;
    }
    prompt
        << regex_replace(text, regex("\\s"), "%20")
        << endl;
    if (!complete_url)
    {
        prompt
            << "With code: "
            << code.user_code
            << endl;
    }
    prompt
        << endl
        << "Hit enter when you have authenticated."
        << endl;
    return prompt.str();
}

int show_prompt(pam_handle_t *pam_handle, const Config &config, const DeviceCode &code)
{
    pam_conv *conv;
    int pam_result = pam_get_item(pam_handle, PAM_CONV, (const void **)&conv);
    if (pam_result != PAM_SUCCESS)
    {
        syslog(LOG_ERR, "show_prompt: pam_get_item failed with result code: %d", pam_result);
        throw PamError();
    }
    // pam message
    pam_message msg;
    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    string prompt = make_prompt(config, code);
    msg.msg = prompt.c_str();
    const pam_message *msg_ptr = &msg;
    pam_response *response_ptr;
    int pam_message_result = (*conv->conv)(1, &msg_ptr, &response_ptr, conv->appdata_ptr);
    if (response_ptr)
    {
        free(response_ptr->resp);
    }
    return pam_message_result;
}

bool is_authorized(const Config &config, const string user, const UserInfo &info)
{
    // Check performing MFA
    if (config.require_mfa && strstr(info.acr.c_str(), "https://refeds.org/profile/mfa") != NULL)
    {
        syslog(LOG_WARNING, "user %s did not perform MFA", info.username.c_str());
        return false;
    }
    // Try to authorize against local config
    if (config.users.count(info.username) > 0)
    {
        if (config.users.find(info.username)->second.count(user) > 0)
        {
            syslog(LOG_INFO, "user %s mapped to %s", info.username.c_str(), user.c_str());
            return true;
        }
    }
    syslog(LOG_WARNING, "cannot find mapping between oauth user %s and local user %s", info.username.c_str(), user.c_str());
    return false;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pam_handle, int flags, int argc, const char **argv)
{
    // NOTE: buffer memory should NOT be freed. When freed the username value
    // stored in the buffer is unavailable to the subsequent PAM modules.
    // For more information see issue #27.
    const char *buffer;
    Config config;
    DeviceCode code;
    AccessToken token;
    UserInfo info;
    // open log
    openlog("pam_oauth2_device", LOG_PID | LOG_NDELAY, LOG_AUTH);
    // load config
    try
    {
        (argc > 0)
            ? load_config(argv[0], &config)
            : load_config("/etc/pam_oauth2_device/config.json", &config);
    }
    catch (nlohmann::json::exception &e)
    {
        syslog(LOG_DEBUG, "pam_sm_authenticate: could not load config: %s", e.what());
        closelog();
        return PAM_AUTH_ERR;
    }
    try
    {
        if (int result = pam_get_user(pam_handle, &buffer, "Username: ") != PAM_SUCCESS)
        {
            syslog(LOG_ERR, "pam_sm_authenticate: pam_get_user failed with result code: %d", result);
            throw PamError();
        }
        // main auth progress
        post_device_code(config, &code);
        show_prompt(pam_handle, config, code);
        post_access_token(config, code, &token);
        get_user_info(config, token, &info);
    }
    catch (PamError &e)
    {
        closelog();
        return PAM_SYSTEM_ERR;
    }
    catch (TimeoutError &e)
    {
        closelog();
        return PAM_AUTH_ERR;
    }
    catch (NetworkError &e)
    {
        closelog();
        return PAM_AUTH_ERR;
    }
    // convert char* to string
    string user = buffer;
    if (is_authorized(config, user, info))
    {
        syslog(LOG_INFO, "authentication succeeded: %s -> %s", info.username.c_str(), user.c_str());
        closelog();
        return PAM_SUCCESS;
    }
    syslog(LOG_INFO, "authentication failed: %s -> %s", info.username.c_str(), user.c_str());
    closelog();
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_CRED_UNAVAIL;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}
