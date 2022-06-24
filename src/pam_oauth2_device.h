#ifndef PAM_OAUTH2_DEVICE_H
#define PAM_OAUTH2_DEVICE_H
#include <string>
#include <map>
#include <set>

using namespace std;

class BaseError : public std::exception
{
public:
    const char *what() const throw() { return "Base Error"; }
};

class PamError : public BaseError
{
public:
    const char *what() const throw() { return "PAM Error"; }
};

class NetworkError : public BaseError
{
public:
    const char *what() const throw() { return "Network Error"; }
};

class TimeoutError : public NetworkError
{
public:
    const char *what() const throw() { return "Timeout Error"; }
};

class ResponseError : public NetworkError
{
public:
    const char *what() const throw() { return "Response Error"; }
};

class Config
{
public:
    string client_id;
    string client_secret;
    string scope;
    string device_code_url;
    string access_token_url;
    string user_info_url;
    string username_attribute;
    string sub_attribute;
    string name_attribute;
    bool require_mfa;
    bool qr_show;
    int qr_error_correction_level;
    map<string, set<string>> users;
};

class DeviceCode
{
public:
    string user_code;
    string device_code;
    string verification_uri;
    string verification_uri_complete;
};

class AccessToken
{
public:
    string access_token;
    string token_type;
    string scope;
};

class UserInfo
{
public:
    string username;
    string name;
    string sub;
    string acr;
};

#endif // PAM_OAUTH2_DEVICE_H
