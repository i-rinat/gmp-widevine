#include <iostream>
#include <string>
#include <boost/format.hpp>
#include <gmp-errors.h>
#include <gmp-platform.h>
#include <gmp-decryption.h>
#include <gmp-async-shutdown.h>
#include "firefoxcdm.hh"


using std::cout;
using std::string;
using boost::format;


const GMPPlatformAPI *platform_api = nullptr;


extern "C" {

GMPErr
GMPInit(const GMPPlatformAPI *aPlatformAPI)
{
    cout << format("%1% aPlatformAPI=%2%\n") % __func__ % aPlatformAPI;
    platform_api = aPlatformAPI;
    return GMPNoErr;
}

GMPErr
GMPGetAPI(const char *apiName, void *aHostAPI, void **aPluginAPI)
{
    cout << format("%1% apiName=%2%, aHostAPI=%3%\n") % __func__ % apiName % aHostAPI;

    string api_name(apiName);

    try {
        if (api_name == GMP_API_DECRYPTOR) {
            *aPluginAPI = new WidevineAdapter();
            return GMPNoErr;

        } else if (api_name == GMP_API_ASYNC_SHUTDOWN) {
            *aPluginAPI = new WidevineAdapterAsyncShutdown(
                                    static_cast<GMPAsyncShutdownHost *>(aHostAPI));
            return GMPNoErr;

        } else {
            return GMPNotImplementedErr;
        }
    } catch (std::exception &e) {
        cout << format("%1% something bad happened: %2%\n") % __func__ % e.what();
        return GMPNotImplementedErr;
    }
}

void
GMPShutdown(void)
{
    cout << format("%1%\n") % __func__;
}

} // extern "C"
