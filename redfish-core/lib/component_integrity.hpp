/*
// Copyright (c) 2023 Google
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/
#pragma once


#include "app.hpp"
#include "dbus_singleton.hpp"
#include "dbus_utility.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "utils/collection.hpp"
#include "utils/dbus_utils.hpp"
#include "utils/json_utils.hpp"

#include <boost/container/flat_map.hpp>
#include <boost/system/error_code.hpp>
#include <boost/url/format.hpp>
#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/message/native_types.hpp>
#include <sdbusplus/unpack_properties.hpp>
#include <sdbusplus/utility/dedup_variant.hpp>

#include <array>
#include <limits>
#include <string_view>
#include <regex>
#include <variant>
#include <vector>
#include <tuple>

namespace redfish
{
// Interfaces which imply a D-Bus object represents a ComponentIntegrity
constexpr std::array<std::string_view, 1> componentIntegrityInterfaces = {
    "xyz.openbmc_project.Inventory.Decorator.ComponentIntegrity"};

using ComponentIntegrityGetParamsVariant =
    std::variant<std::monostate, bool, std::string,
    sdbusplus::message::object_path,
    std::vector<sdbusplus::message::object_path>>;

/**
 * Map a given vector of D-Bus object path to an array of Redfish
 * URI.
 *
 * @param[in]       property1       Redfish property name.
 * @param[in]       property2       Optional second Redfish property name.
 * @param[in]       nodeList        vector of path string.
 *
 * @return          entities        Array of Redfish URI in json.
 */
inline std::optional<nlohmann::json> mapObjectPathVector(
    const std::string& property1,
    const std::string& property2,
    const std::vector<std::string>& pathList)
{
    nlohmann::json entities = nlohmann::json::array();

    for (const std::string& node: pathList)
    {
        sdbusplus::message::object_path path(node);
        std::string entityId = path.filename();
        if (entityId.empty())
        {
            BMCWEB_LOG_ERROR << "Invalid object path:"
                             << property1 <<" " <<property2 << ":" << path.str;
            return std::nullopt;
        }

        nlohmann::json::object_t entity;
        if (property2 == "")
            entity["@odata.id"] = boost::urls::format(
                    "/redfish/v1/{}/{}", property1, entityId);
        else
            entity["@odata.id"] = boost::urls::format(
                    "/redfish/v1/{}/{}/{}", property1, property2, entityId);
        entities.push_back(std::move(entity));
    }

    return {std::move(entities)};
}

inline std::optional<nlohmann::json>
    getTrustedComponent(const std::string& dbusPath)
{
    nlohmann::json::object_t trustedComponent;
    std::string chassis;
    std::string component;

    // Map D-Bus object path to the Redfish URI
    // Example targetComponentURI
    //     "/xyz/openbmc_project/Chassis/chassis01/TrustedComponent/tc01"
    // which should maps to
    //     "/redfish/v1/Chassis/chassis01/TrustedComponent/tc01"

    std::regex re("/xyz/openbmc_project/Chassis/(\\w+)/TrustedComponent/(\\w+)");
    std::smatch matches;

    if (regex_match(dbusPath, matches, re)) {
        chassis = matches[1];
        component = matches[2];
    } else {
        BMCWEB_LOG_ERROR << "Can't parse TrustedComponent object path:"
                         << dbusPath;
        return std::nullopt;
    }

    trustedComponent["@odata.id"] = boost::urls::format(
        "/redfish/v1/Chassis/{}/TrustedComponent/{}", chassis, component);

    return {std::move(trustedComponent)};
}

inline std::optional<nlohmann::json>
    getSystemCert(const std::string& dbusPath)
{
    nlohmann::json::object_t certObj;
    std::string system;
    std::string cert;

    // Map D-Bus object to Redfish URI
    // Example system cert object path: 
    //     "/xyz/openbmc_project/certs/systems/system01/cert01"
    // which should maps to:
    //     "/redfish/v1/Systems/system01/Certificates/cert01"
    std::regex re("/xyz/openbmc_project/certs/systems/(\\w+)/(\\w+)");
    std::smatch matches;

    if (regex_match(dbusPath, matches, re)) {
        system = matches[1];
        cert = matches[2];
    } else {
        BMCWEB_LOG_ERROR << "Can't parse DBus certificate object path:"
                         << dbusPath;
        return std::nullopt;
    }

    certObj["@odata.id"] = boost::urls::format(
        "/redfish/v1/Systems/{}/Certificates/{}", system, cert);

    return {std::move(certObj)};
}

/**
 * @brief Fill out ComponentIntegrity related info by
 * requesting data from the given D-Bus object.
 *
 * @param[in,out]   aResp       Async HTTP response.
 * @param[in]       service     D-Bus service to query.
 * @param[in]       objPath     D-Bus object to query.
 */
inline void getComponentIntegrityData(std::shared_ptr<bmcweb::AsyncResp> aResp,
                             const std::string& service,
                             const std::string& objPath)
{
    BMCWEB_LOG_DEBUG << "Get ComponentIntegrity Data";
    sdbusplus::asio::getAllProperties(
        *crow::connections::systemBus, service, objPath,
        "xyz.openbmc_project.Inventory.Decorator.ComponentIntegrity",
        [objPath, aResp{std::move(aResp)}](
            const boost::system::error_code& ec,
            const std::vector<std::pair<std::string, ComponentIntegrityGetParamsVariant>> & properties) {
        if (ec)
        {
            BMCWEB_LOG_DEBUG << "DBUS response error";
            messages::internalError(aResp->res);
            return;
        }

        const bool* enabled = nullptr;
        const std::string* type = nullptr;
        const std::string* typeVersion = nullptr;
        const std::string* lastUpdated = nullptr;
        //const std::string* targetComponentURI = nullptr;
        //const std::vector<sdbusplus::message::object_path>* componentsProtected = nullptr;

        const bool success = sdbusplus::unpackPropertiesNoThrow(
            dbus_utils::UnpackErrorPrinter(), properties, "Enabled",
            enabled, "Type", type, "TypeVersion", typeVersion,
            "LastUpdated", lastUpdated);

        if (!success)
        {
            messages::internalError(aResp->res);
            return;
        }

        if (enabled!= nullptr)
        {
            if (*enabled)
                aResp->res.jsonValue["ComponentIntegrityEnabled"] = "true";
            else
                aResp->res.jsonValue["ComponentIntegrityEnabled"] = "false";
        }

        if ((type != nullptr) && !type->empty())
        {
            if (*type == "xyz.openbmc_project.Inventory.Decorator.ComponentIntegrity.SecurityTechnologyType.SPDM")
                aResp->res.jsonValue["ComponentIntegrityType"] = "SPDM";
            else if (*type == "xyz.openbmc_project.Inventory.Decorator.ComponentIntegrity.SecurityTechnologyType.TPM")
                aResp->res.jsonValue["ComponentIntegrityType"] = "TPM";
            else if (*type == "xyz.openbmc_project.Inventory.Decorator.ComponentIntegrity.SecurityTechnologyType.OEM")
                aResp->res.jsonValue["ComponentIntegrityType"] = "OEM";
            else {
                messages::internalError(aResp->res);
                return;
            }
        }

        if ((typeVersion != nullptr) && !typeVersion->empty())
        {
            aResp->res.jsonValue["ComponentIntegrityTypeVersion"] = *typeVersion;
        }

        if ((lastUpdated != nullptr) && !lastUpdated->empty())
        {
            aResp->res.jsonValue["LastUpdated"] = *lastUpdated;
        }

        // Get trusted components info from associations.
        std::string targetComponentPath = objPath + "/reporting";
        dbus::utility::getAssociationEndPoints(
            targetComponentPath,
            [aResp](
                const boost::system::error_code& e,
                const dbus::utility::MapperEndPoints& nodeTrustedComponentList) {
            if (e)
            {
                if (e.value() != EBADR)
                {
                    messages::internalError(aResp->res);
                    return;
                }
            }

            // One ComponentIntegrity object should be associated with one
            // TrustedComponent object
            if (nodeTrustedComponentList.size() == 1) {
                const std::string targetComponentURI = nodeTrustedComponentList.at(0);

                std::optional<nlohmann::json> targetComponent =
                    getTrustedComponent(targetComponentURI);
                aResp->res.jsonValue["TargetComponentURI"] = *targetComponent;
            } else { 
                BMCWEB_LOG_DEBUG << "Unexpected TargetComponent #objs (expecting 1): "
                                    << nodeTrustedComponentList.size();
                messages::internalError(aResp->res);
                return;
            }

            });

        // Get protected components info from associations.
        std::string protectedComponentPath = objPath + "/protecting";
        dbus::utility::getAssociationEndPoints(
            protectedComponentPath,
            [aResp](
                const boost::system::error_code& e,
                const dbus::utility::MapperEndPoints& nodeProtectedComponentList) {
            if (e)
            {
                if (e.value() != EBADR)
                {
                    messages::internalError(aResp->res);
                    return;
                }
            }

            // One ComponentIntegrity object may be associated with one
            // or more protectedComponents objects
            if (nodeProtectedComponentList.size() >= 1) {
                std::optional<nlohmann::json> components =
                    mapObjectPathVector("Systems", "", nodeProtectedComponentList);
                if (!components)
                {
                    messages::internalError(aResp->res);
                    return;
                }
                aResp->res.jsonValue["ComponentsProtected"] = *components;
            } else { 
                BMCWEB_LOG_DEBUG << "No protected component objects found!";
                return;
            }

            });

        });
}

/**
 * @brief Fill out ComponentIntegrity#SPDM#IdentityAuthentication
 * related info by requesting data from the given D-Bus object.
 *
 * @param[in,out]   aResp       Async HTTP response.
 * @param[in]       service     D-Bus service to query.
 * @param[in]       objPath     D-Bus object to query.
 */
inline void getSPDMAuthenticationData(std::shared_ptr<bmcweb::AsyncResp> aResp,
                             const std::string& service,
                             const std::string& objPath)
{
    BMCWEB_LOG_DEBUG << "Get ComponentIntegrity#SPDM#IdentyAuthentication Data";
    sdbusplus::asio::getAllProperties(
        *crow::connections::systemBus, service, objPath,
        "xyz.openbmc_project.Inventory.Decorator.IdentityAuthentication",
        [objPath, aResp{std::move(aResp)}](
            const boost::system::error_code& ec,
            const dbus::utility::DBusPropertiesMap& properties) {
        if (ec)
        {
            BMCWEB_LOG_DEBUG << "DBUS response error";
            messages::internalError(aResp->res);
            return;
        }

        const std::string* respStatus = nullptr;

        const bool success = sdbusplus::unpackPropertiesNoThrow(
            dbus_utils::UnpackErrorPrinter(), properties,
            "ResponderVerificationStatus", respStatus);

        if (!success)
        {
            messages::internalError(aResp->res);
            return;
        }

        if (respStatus != nullptr && !respStatus->empty())
        {
            if (*respStatus ==
                "xyz.openbmc_project.Inventory.Decorator.IdentityAuthentication.VerificationStatus.Success")
                aResp->res.jsonValue["ResponderVericationStatus"] = "Success";
            else
                aResp->res.jsonValue["ResponderVericationStatus"] = "Failed";
        }

        // Get associated certs objects.
        std::string reqCertPath = objPath + "/requester_identitified_by";
        dbus::utility::getAssociationEndPoints(
            reqCertPath,
            [aResp](
                const boost::system::error_code& e,
                const dbus::utility::MapperEndPoints& nodeReqCertList) {
            if (e)
            {
                if (e.value() != EBADR)
                {
                    messages::internalError(aResp->res);
                    return;
                }
            }

            nlohmann::json& json = aResp->res.jsonValue;

            // One ComponentIntegrity object should be associated with one
            // requester certificate object
            if (nodeReqCertList.size() == 1) {
                const std::string certPath = nodeReqCertList.at(0);

                std::optional<nlohmann::json> reqCertObj =
                    getSystemCert(certPath);

                json["RequesterAuthentication"] = *reqCertObj;
            } else { 
                BMCWEB_LOG_DEBUG << "Unexpected Requester Cert #objs (expecting 1): "
                                    << nodeReqCertList.size();
                messages::internalError(aResp->res);
                return;
            }

            });

        // Get associated response certs objects.
        std::string respCertPath = objPath + "/responder_identitified_by";
        dbus::utility::getAssociationEndPoints(
            respCertPath,
            [aResp](
                const boost::system::error_code& e,
                const dbus::utility::MapperEndPoints& nodeRespCertList) {
            if (e)
            {
                if (e.value() != EBADR)
                {
                    messages::internalError(aResp->res);
                    return;
                }
            }

            nlohmann::json& json = aResp->res.jsonValue;

            // One ComponentIntegrity object should be associated with one
            // responder certificate object
            if (nodeRespCertList.size() == 1) {
                const std::string certPath = nodeRespCertList.at(0);

                std::optional<nlohmann::json> respCertObj =
                    getSystemCert(certPath);

                json["RequesterAuthentication"] = *respCertObj;
            } else { 
                BMCWEB_LOG_DEBUG << "Unexpected Responder Cert #objs (expecting 1): "
                                    << nodeRespCertList.size();
                messages::internalError(aResp->res);
                return;
            }

            });

        });
}

inline void getComponentData(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                             const std::string& objectPath,
                             const dbus::utility::MapperServiceMap& serviceMap)
{
    for (const auto& [serviceName, interfaceList] : serviceMap)
    {
        for (const auto& interface : interfaceList)
        {
            if (interface == "xyz.openbmc_project.Inventory.Decorator.ComponentIntegrity")
            {
                getComponentIntegrityData(aResp, serviceName, objectPath);
            }
            else if (interface ==
                "xyz.openbmc_project.Inventory.Decorator.IdentityAuthentication")
            {
                getSPDMAuthenticationData(aResp, serviceName, objectPath);
            }
        }
    }
}

/**
 * Find the D-Bus object representing the requested ComponentIntegrity,
 * and call the handler with the results. If matching object is not
 * found, add 404 error to response and don't call the handler.
 *
 * @param[in,out]   resp            Async HTTP response.
 * @param[in]       processorId     Redfish Processor Id.
 * @param[in]       handler         Callback to continue processing request upon
 *                                  successfully finding object.
 */
template <typename Handler>
inline void getComponentObject(const std::shared_ptr<bmcweb::AsyncResp>& resp,
                               const std::string& componentId,
                               Handler&& handler)
{
    BMCWEB_LOG_DEBUG << "Get available system component integrity resources.";

    // GetSubTree on all interfaces which provide info about a component_integrity.
    constexpr std::array<std::string_view, 3> interfaces = {
                "xyz.openbmc_project.Inventory.Decorator.ComponentIntegrity",
                "xyz.openbmc_project.Inventory.Decorator.IdentityAuthentication",
                "xyz.openbmc_project.Inventory.Decorator.MeasurementSet"};
    dbus::utility::getSubTree(
        "/xyz/openbmc_project/ComponentIntegrity/", 0, interfaces,
        [resp, componentId, handler = std::forward<Handler>(handler)](
            const boost::system::error_code& ec,
            const dbus::utility::MapperGetSubTreeResponse& subtree) {
        if (ec)
        {
            BMCWEB_LOG_DEBUG << "DBUS response error: " << ec;
            messages::internalError(resp->res);
            return;
        }
        for (const auto& [objectPath, serviceMap] : subtree)
        {
            // Ignore any objects which don't end with our desired
            // componentintegrity name
            if (!objectPath.ends_with(componentId))
            {
                continue;
            }

            bool found = false;
            // Filter out objects that don't have the ComponentIntegrity-specific
            // interfaces to make sure we can return 404 on non-ComponentIntegrity
            for (const auto& [serviceName, interfaceList] : serviceMap)
            {
                if (std::find_first_of(
                        interfaceList.begin(), interfaceList.end(),
                        componentIntegrityInterfaces.begin(),
                        componentIntegrityInterfaces.end()) != interfaceList.end())
                {
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                continue;
            }

            // Process the first object which does match component name and
            // required interfaces, and potentially ignore any other
            // matching objects. Assume all interfaces we want to process
            // must be on the same object path.

            handler(objectPath, serviceMap);
            return;
        }
        messages::resourceNotFound(resp->res, "ComponentIntegrity", componentId);
        });
}

inline void handleComponentIntegrityCollectionGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.jsonValue["@odata.type"] =
        "#ComponentIntegrityCollection.ComponentIntegrityCollection";
    asyncResp->res.jsonValue["@odata.id"] = "/redfish/v1/ComponentIntegrity";
    asyncResp->res.jsonValue["Name"] = "Component Integrity Collection";
    asyncResp->res.jsonValue["Description"] =
        "Collection of Component Integrity";

    collection_util::getCollectionMembers(
        asyncResp,
        boost::urls::url("/redfish/v1/ComponentIntegrity"),
        componentIntegrityInterfaces,
         "/xyz/openbmc_project/ComponentIntegrity");
}

inline void handleComponentIntegrityGet(
    crow::App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& componentId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    asyncResp->res.jsonValue["@odata.type"] =
        "#ComponentIntegrity.ComponentIntegrity";
    asyncResp->res.jsonValue["Name"] = "Component Integrity";
    asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
        "/redfish/v1/ComponentIntegrity/{}", componentId);

    getComponentObject(
        asyncResp, componentId,
        std::bind_front(getComponentData, asyncResp));
}

inline void handleComponentIntegritySPDMGetSignedMeasurementsActionPost(
    App& app, const crow::Request& req,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& componentId)
{
    if (!redfish::setUpRedfishRoute(app, req, asyncResp))
    {
        return;
    }
    BMCWEB_LOG_DEBUG << "Post ComponentIntegrity SPDMGetSignedMeasurements.";

    // GetSubTree on interfaces which provide info about certificate.
    constexpr std::array<std::string_view, 1> interfaces = {
            "xyz.openbmc_project.Inventory.Decorator.MeasurementSet"};

    dbus::utility::getSubTree(
        "/xyz/openbmc_project/ComponentIntegrity/", 0, interfaces,
        [asyncResp, req, componentId](
            const boost::system::error_code& ec,
            const dbus::utility::MapperGetSubTreeResponse& subtree) {
        if (ec)
        {
            BMCWEB_LOG_ERROR << "DBUS response error: " << ec;
            messages::internalError(asyncResp->res);
            return;
        }

        std::string ciPath =
            std::string("/xyz/openbmc_project/ComponentIntegrity/") + componentId;
    
        nlohmann::json reqJson;
        JsonParseResult ret = parseRequestAsJson(req, reqJson);
        if (ret != JsonParseResult::Success)
        {
            // We did not receive JSON request, proceed as it is RAW data
            BMCWEB_LOG_ERROR << "Parse json request failed!";
            messages::internalError(asyncResp->res);
            return; 
        }
    
        // All fields below are optional by DMTF DSP2046_2022.3.pdf
        std::optional<std::string> optNonce = "";
        std::optional<size_t> optSlotId = 0;
        std::optional<std::vector<size_t>> optMeasurementIndices;

        if (!json_util::readJsonPatch(req, asyncResp->res, "SlotId",
                                      optSlotId, "MeasurementIndices",
                                      optMeasurementIndices, "Nonce", optNonce))
        {
            BMCWEB_LOG_ERROR << "Required parameters are missing";
            messages::internalError(asyncResp->res);
            return;
        }

        for (const auto& [objectPath, serviceMap] : subtree)
        {
            // Ignore any objects which don't match component integrity
            if (objectPath.find(ciPath) == std::string::npos)
            {
                continue;
            }

            // Should only match one service and one object
            for (const auto& [serviceName, interfaceList] : serviceMap)
            {
                // SPDMGetSignedMeasurements Response
                using RespStruct =
                    std::tuple<sdbusplus::message::object_path, std::string,
                    std::string, std::string, std::string, std::string>;

                crow::connections::systemBus->async_method_call(
                    [asyncResp](const boost::system::error_code& e,
                                const RespStruct& resp) {
                    if (e)
                    {
                        BMCWEB_LOG_ERROR << "DBUS response error: " << e.message();
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    sdbusplus::message::object_path deviceCert =
                        std::get<0>(resp);
                    std::string hashAlg = std::get<1>(resp);
                    std::string pubkey = std::get<2>(resp);
                    std::string signedMeasurements = std::get<3>(resp);
                    std::string signAlg = std::get<4>(resp);
                    std::string version = std::get<5>(resp);

                    asyncResp->res.jsonValue["@odata.type"] =
                        "#ComponentIntegrity.v1_0_0.SPDMGetSignedMeasurementsResponse";
                    asyncResp->res.jsonValue["Version"] = version;
                    asyncResp->res.jsonValue["HashingAlgorithm"] = hashAlg;
                    asyncResp->res.jsonValue["SigningAlgorithm"] = signAlg;
                    asyncResp->res.jsonValue["SignedMeasurements"] =
                        signedMeasurements;
                    asyncResp->res.jsonValue["PublicKey"] = pubkey;

                    // handle Device Certificate
                    std::optional<nlohmann::json> certObj =
                        getSystemCert(deviceCert);
                    if (!certObj)
                    {
                        messages::internalError(asyncResp->res);
                        return;
                    }

                    asyncResp->res.jsonValue["Certificate"] = *certObj;

                    },
                    serviceName, ciPath,
                    "xyz.openbmc_project.Inventory.Decorator.MeasurementSet",
                    "SPDMGetSignedMeasurements", *optMeasurementIndices, *optNonce, *optSlotId);
            }
        }
    });
}

inline void requestRoutesComponentIntegrityCollection(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/ComponentIntegrity/")
        .privileges(redfish::privileges::getServiceRoot) // TODO add proper privilege
        .methods(boost::beast::http::verb::get)(std::bind_front(
            handleComponentIntegrityCollectionGet, std::ref(app)));
}

inline void requestRoutesComponentIntegrity(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/ComponentIntegrity/<str>/")
        .privileges(redfish::privileges::getServiceRoot) // TODO add proper privilege
        .methods(boost::beast::http::verb::get)(
            std::bind_front(handleComponentIntegrityGet, std::ref(app)));
}

inline void requestRoutesComponentIntegritySPDMGetSignedMeasurementsAction(App& app)
{
    BMCWEB_ROUTE(app,
        "/redfish/v1/ComponentIntegrity/<str>/Actions/ComponentIntegrity.SPDMGetSignedMeasurements/")
        .privileges(redfish::privileges::getServiceRoot) // TODO add proper privilege
        .methods(boost::beast::http::verb::post)(
            std::bind_front(handleComponentIntegritySPDMGetSignedMeasurementsActionPost, std::ref(app)));
}

}// namespace redfish
