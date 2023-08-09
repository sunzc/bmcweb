/*
// Copyright (c) 2023 Google
/
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
#include "dbus_utility.hpp"
#include "query.hpp"
#include "registries/privilege_registry.hpp"
#include "utils/chassis_utils.hpp"
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
// Interfaces which imply a D-Bus object represents a TrustedComponent 
constexpr std::array<std::string_view, 1> trustedComponentInterfaces = {
    "xyz.openbmc_project.Inventory.Item.TrustedComponent"};

using TrustedComponentGetParamsVariant =
    std::variant<std::monostate, std::string,
    sdbusplus::message::object_path,
    std::vector<sdbusplus::message::object_path>>;

/**
 * Find the D-Bus object representing the requested TrustedComponent, and call the
 * handler with the results. If matching object is not found, add 404 error to
 * response and don't call the handler.
 *
 * @param[in,out]   resp            Async HTTP response.
 * @param[in]       componentName   Redfish TrustedComponent Name.
 * @param[in]       handler         Callback to continue processing request upon
 *                                  successfully finding object.
 */
template <typename Handler>
inline void getTrustedComponentObject(const std::shared_ptr<bmcweb::AsyncResp>& resp,
                               const std::string& componentName,
                               Handler&& handler)
{
    BMCWEB_LOG_DEBUG << "Get available chassis trusted_component resources.";

    // GetSubTree on all interfaces which provide info about TrustedComponent 
    constexpr std::array<std::string_view, 1> interfaces = {
        "xyz.openbmc_project.Inventory.Item.TrustedComponent"};
    dbus::utility::getSubTree(
        "/xyz/openbmc_project/Chassis/", 0, interfaces,
        [resp, componentName, handler = std::forward<Handler>(handler)](
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
            // Ignore any objects which don't end with our desired component name
            if (!objectPath.ends_with(componentName))
            {
                continue;
            }

            bool found = false;
            for (const auto& [serviceName, interfaceList] : serviceMap)
            {
                if (std::find_first_of(
                        interfaceList.begin(), interfaceList.end(),
                        trustedComponentInterfaces.begin(),
                        trustedComponentInterfaces.end()) != interfaceList.end())
                {
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                continue;
            }

            handler(objectPath, serviceMap);
            return;
        }
        messages::resourceNotFound(resp->res, "TrustedComponent", componentName);
        });
}

/**
 * @brief Fill out TrustedComponent interface related info by
 * requesting data from the given D-Bus object.
 *
 * @param[in,out]   aResp       Async HTTP response.
 * @param[in]       service     D-Bus service to query.
 * @param[in]       objPath     D-Bus object to query.
 */
inline void getTrustedComponentInterfaceData(std::shared_ptr<bmcweb::AsyncResp> aResp,
                             const std::string& service,
                             const std::string& objPath)
{
    BMCWEB_LOG_DEBUG << "Get TrustedComponent Interface Data";
    sdbusplus::asio::getAllProperties(
        *crow::connections::systemBus, service, objPath,
        "xyz.openbmc_project.Inventory.Item.TrustedComponent",
        [objPath, aResp{std::move(aResp)}](
            const boost::system::error_code& ec,
            const std::vector<std::pair<std::string, TrustedComponentGetParamsVariant>> & properties) {
        if (ec)
        {
            BMCWEB_LOG_DEBUG << "DBUS response error";
            messages::internalError(aResp->res);
            return;
        }

        nlohmann::json& json = aResp->res.jsonValue;

        const std::string* type = nullptr;
        const std::string* firmwareVersion = nullptr;
        const std::string* manufacturer = nullptr;
        const std::string* serialNumber = nullptr;
        const std::string* sku = nullptr;
        const std::string* uuid = nullptr;
        const std::string* certificatesLocation = nullptr;

        const bool success = sdbusplus::unpackPropertiesNoThrow(
            dbus_utils::UnpackErrorPrinter(), properties,
            "CertificatesLocation", certificatesLocation, "FirmwareVersion", firmwareVersion,
            "Manufacturer", manufacturer, "SerialNumber", serialNumber,
            "SKU", sku, "TrustedComponentType", type, "UUID", uuid);

        if (!success)
        {
            messages::internalError(aResp->res);
            return;
        }

        if (certificatesLocation != nullptr)
        {
            std::string systemId = *certificatesLocation;
            nlohmann::json::object_t certificatesPath;

            if (systemId.empty()) {
                BMCWEB_LOG_ERROR << "TrustedComponent contains invalid certs!";
                messages::internalError(aResp->res);
                return;
            }

            certificatesPath["@odata.id"] = boost::urls::format(
                    "/redfish/v1/Systems/{}/Certificates", systemId);
            json["Certificates"] = std::move(certificatesPath);
        }

        if ((firmwareVersion!= nullptr) && !firmwareVersion->empty())
        {
            aResp->res.jsonValue["FirmwareVersion"] = *firmwareVersion;
        }

        // Get active software image info from associations.
        std::string activeSoftwarePath = objPath + "/actively_running";
        dbus::utility::getAssociationEndPoints(
            activeSoftwarePath,
            [aResp](
                const boost::system::error_code& e,
                const dbus::utility::MapperEndPoints& nodeActiveSoftwareList) {
            if (e)
            {
                if (e.value() != EBADR)
                {
                    messages::internalError(aResp->res);
                    return;
                }
            }

            // One TrustedComponent object should be associated with one
            // activeSoftwareImage object
            if (nodeActiveSoftwareList.size() == 1) {
                const std::string softwareImageURI = nodeActiveSoftwareList.at(0);
                sdbusplus::message::object_path
                    activeSoftwareImage(softwareImageURI);
                std::string softwareId = activeSoftwareImage.filename();

                nlohmann::json::object_t imagePath;

                if (softwareId.empty()) {
                    BMCWEB_LOG_ERROR << "TrustedComponent contains invalid activeSoftwareImage:"
                                     << activeSoftwareImage.str;
                    messages::internalError(aResp->res);
                    return;
                }

                imagePath["@odata.id"] = boost::urls::format(
                    "redfish/v1/UpdateService/SoftwareInventory/{}", softwareId);
                aResp->res.jsonValue["ActiveSoftwareImage"] = std::move(imagePath);
            } else { 
                BMCWEB_LOG_DEBUG << "Unexpected ActiveSoftwareImage #objs (expecting 1): "
                                    << nodeActiveSoftwareList.size();
                messages::internalError(aResp->res);
                return;
            }
            });

        // Get ComponentIntegrity info from associations.
        std::string componentIntegrityPath = objPath + "/reported_by";
        dbus::utility::getAssociationEndPoints(
            componentIntegrityPath,
            [aResp](
                const boost::system::error_code& e,
                const dbus::utility::MapperEndPoints& nodeComponentIntegrityList) {
            if (e)
            {
                if (e.value() != EBADR)
                {
                    messages::internalError(aResp->res);
                    return;
                }
            }

            if (nodeComponentIntegrityList.size() >= 1) {
                std::optional<nlohmann::json> components =
                    mapObjectPathVector("ComponentIntegrity", "", nodeComponentIntegrityList);
                if (!components)
                {
                    BMCWEB_LOG_ERROR << "ComponentIntegrity is invalid.";
                    messages::internalError(aResp->res);
                    return;
                }
                aResp->res.jsonValue["ComponentIntegrity"] = *components;
            } else { 
                BMCWEB_LOG_DEBUG << "No ComponentIntegrity objects found!";
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

            // One TrustedComponent object may be associated with one
            // or more protectedComponents objects
            if (nodeProtectedComponentList.size() >= 1) {
                std::optional<nlohmann::json> components =
                    mapObjectPathVector("Systems", "", nodeProtectedComponentList);
                if (!components)
                {
                    BMCWEB_LOG_ERROR << "TrustedComponent: no protected components found.";
                    return;
                }
                aResp->res.jsonValue["ComponentsProtected"] = *components;
            } else { 
                BMCWEB_LOG_DEBUG << "No protected component objects found!";
                return;
            }
            });

        // Get integratedInto info from associations.
        std::string integratedInto = objPath + "/integrated_into";
        dbus::utility::getAssociationEndPoints(
            integratedInto,
            [aResp](
                const boost::system::error_code& e,
                const dbus::utility::MapperEndPoints& nodeIntegratedIntoList) {
            if (e)
            {
                if (e.value() != EBADR)
                {
                    messages::internalError(aResp->res);
                    return;
                }
            }

            // One TrustedComponent object should be associated with one
            // integratedInto object
            if (nodeIntegratedIntoList.size() == 1) {
                const std::string integratedIntoURI = nodeIntegratedIntoList.at(0);
                sdbusplus::message::object_path
                    integratedIntoObj(integratedIntoURI);
                std::string systemId = integratedIntoObj.filename();

                nlohmann::json::object_t integratedPath;

                if (systemId.empty()) {
                    BMCWEB_LOG_ERROR << "TrustedComponent contains invalid IntegratedInto : "
                                     << integratedIntoObj.str;
                    messages::internalError(aResp->res);
                    return;
                }

                integratedPath["@odata.id"] = boost::urls::format(
                        "/redfish/v1/Systems/{}", systemId);
                aResp->res.jsonValue["IntegratedInto"] = std::move(integratedPath);
            } else { 
                BMCWEB_LOG_ERROR << "TrustedComponent contains no IntegratedInto!";
                return;
            }
            });

        // Get software images info from associations.
        std::string softwareImagesPath = objPath + "/runs";
        dbus::utility::getAssociationEndPoints(
            softwareImagesPath,
            [aResp](
                const boost::system::error_code& e,
                const dbus::utility::MapperEndPoints& nodeSoftwareImagesList) {
            if (e)
            {
                if (e.value() != EBADR)
                {
                    messages::internalError(aResp->res);
                    return;
                }
            }

            // One TrustedComponent object may be associated with one
            // or more SoftwareImage objects
            if (nodeSoftwareImagesList.size() >= 1) {
                std::optional<nlohmann::json> images =
                    mapObjectPathVector("UpdateService", "SoftwareInventory", nodeSoftwareImagesList);
                if (!images)
                {
                    BMCWEB_LOG_ERROR << "SoftwareImages is invalid.";
                    messages::internalError(aResp->res);
                    return;
                }
                aResp->res.jsonValue["SoftwareImages"] = *images;
            } else { 
                BMCWEB_LOG_DEBUG << "No software image objects found!";
                return;
            }
            });

        if ((type != nullptr) && !type->empty())
        {
            if (*type ==
                "xyz.openbmc_project.Inventory.Item.TrustedComponent.ComponentAttachType.Discrete")
                aResp->res.jsonValue["TrustedComponentType"] = "Discrete";
            else if (*type ==
                "xyz.openbmc_project.Inventory.Item.TrustedComponent.ComponentAttachType.Integrated")
                aResp->res.jsonValue["TrustedComponentType"] = "Integrated";
            else {
                messages::internalError(aResp->res);
                return;
            }
        }

        if ((manufacturer != nullptr) && !manufacturer->empty())
        {
            aResp->res.jsonValue["Manufacturer"] = *manufacturer;
        }

        if ((serialNumber != nullptr) && !serialNumber->empty())
        {
            aResp->res.jsonValue["SerialNumber"] = *serialNumber;
        }

        if ((sku != nullptr) && !sku->empty())
        {
            aResp->res.jsonValue["SKU"] = *sku;
        }

        if ((uuid != nullptr) && !uuid->empty())
        {
            aResp->res.jsonValue["UUID"] = *uuid;
        }
        });
}

inline void getTrustedComponentData(const std::shared_ptr<bmcweb::AsyncResp>& aResp,
                             const std::string& objectPath,
                             const dbus::utility::MapperServiceMap& serviceMap)
{
    for (const auto& [serviceName, interfaceList] : serviceMap)
    {
        for (const auto& interface : interfaceList)
        {
            if (interface == "xyz.openbmc_project.Inventory.Item.TrustedComponent")
            {
                getTrustedComponentInterfaceData(aResp, serviceName, objectPath);
            }
        }
    }
}


inline void requestRoutesTrustedComponent(App& app)
{

    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/TrustedComponent/<str>")
        .privileges(redfish::privileges::getServiceRoot) // TODO: define privileges
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& chassisName,
                   const std::string& componentName) {
        if (!redfish::setUpRedfishRoute(app, req, asyncResp))
        {
            return;
        }

        asyncResp->res.addHeader(
            boost::beast::http::field::link,
            "</redfish/v1/JsonSchemas/TrustedComponent/TrustedComponent.json>; rel=describedby");
        asyncResp->res.jsonValue["@odata.type"] =
            "#TrustedComponent.v1_0_0.TrustedComponent";
        asyncResp->res.jsonValue["@odata.id"] = boost::urls::format(
                    "/redfish/v1/Chassis/{}/TrustedComponent/{}",
                    chassisName, componentName);

        getTrustedComponentObject(
            asyncResp, componentName,
            std::bind_front(getTrustedComponentData, asyncResp));
        });
}

inline void requestRoutesTrustedComponentCollection(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Chassis/<str>/TrustedComponent/")
        .privileges(redfish::privileges::getServiceRoot)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request& req,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& chassisName) {

        boost::urls::url url = boost::urls::format(
            "/redfish/v1/Chassis/{}/TrustedComponent", chassisName);

        if (!redfish::setUpRedfishRoute(app, req, asyncResp))
        {
            return;
        }
        asyncResp->res.jsonValue["@odata.type"] =
            "#TrustedComponentCollection.TrustedComponentCollection";
        asyncResp->res.jsonValue["@odata.id"] = url;
        asyncResp->res.jsonValue["Name"] = "Trusted Component Collection";
        asyncResp->res.jsonValue["Description"] =
            "Collection of Trusted Component";

        collection_util::getCollectionMembers(
            asyncResp,
            url,
            trustedComponentInterfaces,
             "/xyz/openbmc_project/Chassis/");
        });
}

} // namespace redfish
