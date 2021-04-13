# OAuth2/OpenID Based Authentication handler for Wordpress REST API

Wordpress REST API authentication with [WSO2 Identity server](https://wso2.com/identity-and-access-management/) (OAuth2/OpenID)

This plugin adds wordpress REST API based on extrenal Identity Server and i have tested with WSO2 Identity Server but this wil work with other identity servers with minimum changes. This has been built as a demo version for one of my developmet team and i am publishing this here in order to share the code who ever searching for this kind of a requirnment. 

Also this has been based on the basic [auth plugin](https://github.com/WP-API/Basic-Auth) published by [Wordpress API Team](https://github.com/WP-API).

## How it works
If everything setup correctly the plugin will scan incoming API requests for authorization header. If found it will check the access token validation and expiration with WSO2 Identity Server Usreinfo endpoint and introspect endpoint. If everything validated the plugin will save the access token and expiration time in the local database. So the upcoming request with same access token wont cross check with the WSO2 Identity Server. If access token is not validated http 403 will be returned, Database has the expiration time and will only allow to access the relevant access token within the valid time period.

## Installing
1. Download the plugin into your plugins directory
2. Enable in the WordPress admin

## Using
Navigate to the settings->OAuth2/OpenID section and set following parameters

* Userinfo Endpoint - WSO2 Identity Server Userinfo endpoint
* Token Validation Endpoint - WSO2 Identity Server introspect endpoint
* Username - WSO2 Identity Server admn user username
* Password - WSO2 Identity Server admn user password
* Skip SSL Verification - Skip SSL Validations in DEV mode





