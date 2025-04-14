/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <regex>

#include <aos/common/crypto/utils.hpp>

#include "utils/exception.hpp"
#include "utils/pkcs11helper.hpp"

namespace aos::common::utils {

/***********************************************************************************************************************
 * Statics
 **********************************************************************************************************************/

// Creates RFC7512 URL adapted for PKCS11 provider:
// https://www.rfc-editor.org/rfc/rfc7512.html
static std::string CreatePKCS11ProviderPrivKeyURL(const String& url)
{
    std::string result;

    try {
        // libp11 v0.4.11(provided with Ubuntu 22.04) loads pkcs11 objects with invalid id if label available.
        // Remove label to protect against loading invalid objects.
        std::regex objLabelRegex {"object=[^&?;]*[&?;]?"};

        result = std::regex_replace(url.CStr(), objLabelRegex, "");

        // pkcs11-provider doesn't process module-path
        std::regex modulePathRegex {"module\\-path=[^&?;]*[&?;]?"};

        result = std::regex_replace(result, modulePathRegex, "");

        // pkcs11-provider tools/uri2pem.py requires type=private, make url compatible with it.
        std::regex pkcs11PrefixRegex {"^pkcs11:"};

        result = std::regex_replace(result, pkcs11PrefixRegex, "pkcs11:type=private;");
    } catch (const std::exception& e) {
        AOS_ERROR_THROW(e.what(), aos::ErrorEnum::eFailed);
    }

    return result;
}

/***********************************************************************************************************************
 * Public functions
 **********************************************************************************************************************/

RetWithError<std::string> CreatePKCS11PrivKeyURL(const String& keyURL)
{
    try {
        return {CreatePKCS11ProviderPrivKeyURL(keyURL), ErrorEnum::eNone};
    } catch (const std::exception& e) {
        return {"", AOS_ERROR_WRAP(utils::ToAosError(e))};
    }
}

} // namespace aos::common::utils
