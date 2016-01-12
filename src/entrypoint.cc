/*
 * Copyright © 2016  Rinat Ibragimov
 *
 * This file is part of gmp-widevine.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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
    LOGF << format("GMPInit aPlatformAPI=%1%\n") % aPlatformAPI;
    fxcdm::set_platform_api(aPlatformAPI);

    return GMPNoErr;
}

GMPErr
GMPGetAPI(const char *apiName, void *aHostAPI, void **aPluginAPI)
{
    LOGF << format("GMPGetAPI apiName=%1%, aHostAPI=%2%\n") % apiName % aHostAPI;

    string api_name(apiName);

    try {
        if (api_name == GMP_API_DECRYPTOR) {

            *aPluginAPI = new fxcdm::Module();
            return GMPNoErr;

        } else if (api_name == GMP_API_ASYNC_SHUTDOWN) {

            *aPluginAPI = new fxcdm::ModuleAsyncShutdown(
                                    static_cast<GMPAsyncShutdownHost *>(aHostAPI));
            return GMPNoErr;

        } else if (api_name == GMP_API_VIDEO_DECODER) {

            *aPluginAPI = new fxcdm::VideoDecoder(static_cast<GMPVideoHost *>(aHostAPI));
            return GMPNoErr;

        } else {
            return GMPNotImplementedErr;
        }
    } catch (std::exception &e) {
        LOGZ << format("GMPGetAPI: something bad happened: %2%\n") % e.what();
        return GMPNotImplementedErr;
    }
}

void
GMPShutdown()
{
    LOGF << "GMPShutdown\n";
}

} // extern "C"

namespace {

// ensure signatures are correct
GMPInitFunc     gmp_init_ptr     __attribute__((unused)) = GMPInit ;
GMPGetAPIFunc   gmp_get_api_ptr  __attribute__((unused)) = GMPGetAPI;
GMPShutdownFunc gmp_shutdown_ptr __attribute__((unused)) = GMPShutdown;

} // anonymous namespace
