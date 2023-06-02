#include "irods/irods_report_plugins_in_json.hpp"
#include "irods/checksum.h"
#include "irods/SHA256Strategy.hpp"
#include "irods/irods_logger.hpp"

#include <fmt/format.h>

#include <cstring>

using json = nlohmann::json;
using log_api = irods::experimental::log::api;

namespace irods {

    error add_plugin_type_to_json_array(
        const std::string& _plugin_type,
        const char* _type_name,
        json& _json_array)
    {
        std::string plugin_home;
        error ret = resolve_plugin_path( _plugin_type, plugin_home );
        if (!ret.ok()) {
            return PASS( ret );
        }

        plugin_name_generator name_gen;
        plugin_name_generator::plugin_list_t plugin_list;
        ret = name_gen.list_plugins( plugin_home, plugin_list );
        if ( !ret.ok() ) {
            return PASS( ret );
        }

        for (plugin_name_generator::plugin_list_t::iterator itr = plugin_list.begin();
             itr != plugin_list.end();
             ++itr)
        {
            const auto filepath = fmt::format("{}lib{}.so", plugin_home, *itr);

            char checksum[NAME_LEN]{};
            int ret = chksumLocFile(filepath.c_str(), checksum, irods::SHA256_NAME.c_str());

            if (ret < 0) {
                log_api::error("Failed to calculate checksum for plugin: [{}], status = {}", *itr, ret);
                std::strncpy(checksum, "", sizeof(checksum));
            }

            json plug{
                {"name", itr->c_str()},
                {"type", _type_name},
                {"version", ""},
                {"checksum_sha256", checksum + std::strlen("sha2:")} // Add checksum without sha2: prefix
            };

            _json_array.push_back(plug);
        }

        return SUCCESS();
    }

    error get_plugin_array(json& _plugins)
    {
        _plugins = json::array();

        error ret = add_plugin_type_to_json_array( KW_CFG_PLUGIN_TYPE_RESOURCE, "resource", _plugins );
        if ( !ret.ok() ) {
            return PASS( ret );
        }

        std::string svc_role;
        ret = get_catalog_service_role(svc_role);
        if(!ret.ok()) {
            log(PASS(ret));
            return PASS( ret );
        }

        if( KW_CFG_SERVICE_ROLE_PROVIDER == svc_role ) {
            ret = add_plugin_type_to_json_array( KW_CFG_PLUGIN_TYPE_DATABASE, "database", _plugins );
            if ( !ret.ok() ) {
                return PASS( ret );
            }
        }

        ret = add_plugin_type_to_json_array( KW_CFG_PLUGIN_TYPE_AUTHENTICATION, "authentication", _plugins );
        if ( !ret.ok() ) {
            return PASS( ret );
        }

        ret = add_plugin_type_to_json_array( KW_CFG_PLUGIN_TYPE_NETWORK, "network", _plugins );
        if ( !ret.ok() ) {
            return PASS( ret );
        }

        ret = add_plugin_type_to_json_array( KW_CFG_PLUGIN_TYPE_API, "api", _plugins );
        if ( !ret.ok() ) {
            return PASS( ret );
        }

        ret = add_plugin_type_to_json_array( KW_CFG_PLUGIN_TYPE_MICROSERVICE, "microservice", _plugins );
        if ( !ret.ok() ) {
            return PASS( ret );
        }

        return SUCCESS();
    } // get_plugin_array

    error serialize_resource_plugin_to_json(const resource_ptr& _resc, json& _entry)
    {
        if (_entry.is_null()) {
            return ERROR(SYS_NULL_INPUT, "null json object _entry");
        }

        std::string host_name;
        error ret = _resc->get_property< std::string >( irods::RESOURCE_LOCATION, host_name );
        if ( !ret.ok() ) {
            return PASS(ret);
        }

        rodsLong_t id;
        ret = _resc->get_property< rodsLong_t >( irods::RESOURCE_ID, id );
        if ( !ret.ok() ) {
            return PASS(ret);
        }

        std::string name;
        ret = _resc->get_property< std::string >( irods::RESOURCE_NAME, name );
        if ( !ret.ok() ) {
            return PASS(ret);
        }

        std::string type;
        ret = _resc->get_property< std::string >( irods::RESOURCE_TYPE, type );
        if ( !ret.ok() ) {
            return PASS(ret);
        }

        std::string vault;
        ret = _resc->get_property< std::string >( irods::RESOURCE_PATH, vault );
        if ( !ret.ok() ) {
            return PASS(ret);
        }

        std::string context;
        ret = _resc->get_property< std::string >( irods::RESOURCE_CONTEXT, context );
        if ( !ret.ok() ) {
            return PASS(ret);
        }

        std::string parent;
        ret = _resc->get_property< std::string >( irods::RESOURCE_PARENT, parent );
        if ( !ret.ok() ) {
            return PASS(ret);
        }

        std::string parent_context;
        ret = _resc->get_property< std::string >( irods::RESOURCE_PARENT_CONTEXT, parent_context );
        if ( !ret.ok() ) {
            return PASS(ret);
        }

        std::string freespace;
        ret = _resc->get_property< std::string >( irods::RESOURCE_FREESPACE, freespace );
        if ( !ret.ok() ) {
            return PASS(ret);
        }

        std::string comments;
        ret = _resc->get_property< std::string >( irods::RESOURCE_COMMENTS, comments );
        if ( !ret.ok() ) {
            return PASS(ret);
        }
        std::string info;
        ret = _resc->get_property< std::string >( irods::RESOURCE_INFO, info );
        if ( !ret.ok() ) {
            return PASS(ret);
        }

        int status = 0;
        ret = _resc->get_property< int >( irods::RESOURCE_STATUS, status );
        if ( !ret.ok() ) {
            return PASS(ret);
        }

        _entry["name"] = name;
        _entry["id"] =  std::to_string( id );
        _entry["type"] = type;
        _entry["host"] = host_name;
        _entry["vault_path"] = vault;
        _entry["context_string"] = context;
        _entry["parent_resource"] = parent;
        _entry["parent_context"] = parent_context;
        _entry["free_space"] = freespace;
        _entry["comments"] = comments;
        _entry["info"] = info;
        _entry["status"] = (status != INT_RESC_STATUS_DOWN) ? "up" : "down";

        return SUCCESS();
    }

}; // namespace irods
