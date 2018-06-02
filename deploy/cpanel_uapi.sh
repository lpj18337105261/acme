#!/usr/bin/env sh
# Here is the script to deploy the cert to your cpanel using the cpanel API.
# Uses command line uapi.  --user option is needed only if run as root.
# Returns 0 when success.
# Written by Santeri Kannisto <santeri.kannisto@webseodesigners.com>
# Public domain, 2017

#export DEPLOY_CPANEL_USER=myusername

########  Private functions #####################

__urlencode() {
  local string="${1}"
  local strlen=${#string}
  local encoded=""
  local pos c o

  for ((pos = 0; pos < strlen; pos++)); do
    c=${string:$pos:1}
    case "$c" in
      [-_.~a-zA-Z0-9]) o="${c}" ;;
      *) printf -v o '%%%02x' "'$c" ;;
    esac
    encoded+="${o}"
  done
  echo "${encoded}"
}

########  Public functions #####################

#domain keyfile certfile cafile fullchain

cpanel_uapi_deploy() {
  _cdomain="$1"
  _ckey="$2"
  _ccert="$3"
  _cca="$4"
  _cfullchain="$5"

  _debug _cdomain "$_cdomain"
  _debug _ckey "$_ckey"
  _debug _ccert "$_ccert"
  _debug _cca "$_cca"
  _debug _cfullchain "$_cfullchain"

  if ! _exists uapi; then
    _err "The command uapi is not found."
    return 1
  fi
  if ! _exists php; then
    _err "The command php is not found."
    return 1
  fi
  # read cert and key files and urlencode both
  _certstr=$(cat "$_ccert")
  _keystr=$(cat "$_ckey")
  _cert=$(__urlencode "$_certstr")
  _key=$(__urlencode "$_keystr")

  _debug _cert "$_cert"
  _debug _key "$_key"

  if [ "$(id -u)" = 0 ]; then
    if [ -z "$DEPLOY_CPANEL_USER" ]; then
      _err "It seems that you are root, please define the target user name: export DEPLOY_CPANEL_USER=username"
      return 1
    fi
    _savedomainconf DEPLOY_CPANEL_USER "$DEPLOY_CPANEL_USER"
    _response=$(uapi --user="$DEPLOY_CPANEL_USER" SSL install_ssl domain="$_cdomain" cert="$_cert" key="$_key")
  else
    _response=$(uapi SSL install_ssl domain="$_cdomain" cert="$_cert" key="$_key")
  fi
  error_response="status: 0"
  if test "${_response#*$error_response}" != "$_response"; then
    _err "Error in deploying certificate:"
    _err "$_response"
    return 1
  fi

  _debug response "$_response"
  _info "Certificate successfully deployed"
  return 0
}
