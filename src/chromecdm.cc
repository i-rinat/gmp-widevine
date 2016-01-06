#include "chromecdm.hh"
#include <iostream>
#include <string>
#include <boost/format.hpp>


using std::cout;
using std::string;
using boost::format;


namespace {

void *
get_cdm_host_func(int host_interface_version, void *user_data)
{
    cout << format("get_cdm_host_func host_interface_version=%d, user_data=%p\n") %
            host_interface_version % user_data;

    return nullptr;
}

} // anonymous namespace


namespace crcdm {

void
Initialize()
{
    cout << "crcdm::Initialize before\n";
    INITIALIZE_CDM_MODULE();
    cout << "crcdm::Initialize after\n";
    cout << "GetCdmVersion -> " << GetCdmVersion() << "\n";
}

void
Deinitialize()
{
    DeinitializeCdmModule();
}

cdm::ContentDecryptionModule *
CreateInstance()
{
    const string key_system {"com.widevine.alpha"};

    void *ptr = CreateCdmInstance(cdm::ContentDecryptionModule::kVersion, key_system.c_str(),
                                  key_system.length(), get_cdm_host_func, (void *)0x12345);
    cout << "crcdm::CreateInstance -> " << ptr << "\n";

    return static_cast<cdm::ContentDecryptionModule *>(ptr);
}

} // namespace crcdm
