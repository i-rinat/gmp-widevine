#include <string>
#include <boost/format.hpp>
#include <dlfcn.h>
#include <gmp/gmp-errors.h>
#include <gmp/gmp-entrypoints.h>
#include "firefoxcdm.hh"
#include "chromecdm.hh"
#include "log.hh"


using std::string;
using boost::format;


extern "C" {

GMPErr
GMPInit(const GMPPlatformAPI *aPlatformAPI)
{
    LOGD << format("%1% aPlatformAPI=%2%\n") % __func__ % aPlatformAPI;
    fxcdm::set_platform_api(aPlatformAPI);

    crcdm::Initialize();

    return GMPNoErr;
}

GMPErr
GMPGetAPI(const char *apiName, void *aHostAPI, void **aPluginAPI)
{
    LOGD << format("%1% apiName=%2%, aHostAPI=%3%\n") % __func__ % apiName % aHostAPI;

    string api_name(apiName);

    try {
        if (api_name == GMP_API_DECRYPTOR) {
            *aPluginAPI = new fxcdm::WidevineAdapter();
            return GMPNoErr;

        } else if (api_name == GMP_API_ASYNC_SHUTDOWN) {
            *aPluginAPI = new fxcdm::WidevineAdapterAsyncShutdown(
                                    static_cast<GMPAsyncShutdownHost *>(aHostAPI));
            return GMPNoErr;

        } else {
            return GMPNotImplementedErr;
        }
    } catch (std::exception &e) {
        LOGD << format("%1% something bad happened: %2%\n") % __func__ % e.what();
        return GMPNotImplementedErr;
    }
}

void
GMPShutdown()
{
    LOGD << format("%1%\n") % __func__;
}

} // extern "C"

namespace {

// ensure signatures are correct
GMPInitFunc     gmp_init_ptr     __attribute__((unused)) = GMPInit ;
GMPGetAPIFunc   gmp_get_api_ptr  __attribute__((unused)) = GMPGetAPI;
GMPShutdownFunc gmp_shutdown_ptr __attribute__((unused)) = GMPShutdown;

} // anonymous namespace
