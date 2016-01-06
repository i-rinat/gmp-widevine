#include "chromecdm.hh"
#include "log.hh"
#include <string>
#include <boost/format.hpp>


using std::string;
using boost::format;


namespace {

void *
get_cdm_host_func(int host_interface_version, void *user_data)
{
    LOGD << format("get_cdm_host_func host_interface_version=%d, user_data=%p\n") %
            host_interface_version % user_data;

    return nullptr;
}

} // anonymous namespace


namespace crcdm {

void
Initialize()
{
    LOGD << "crcdm::Initialize\n";
    INITIALIZE_CDM_MODULE();
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
    LOGD << "crcdm::CreateInstance -> " << ptr << "\n";

    return static_cast<cdm::ContentDecryptionModule *>(ptr);
}

} // namespace crcdm
