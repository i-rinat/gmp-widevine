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

#pragma once

#include <gmp/gmp-decryption.h>
#include <gmp/gmp-async-shutdown.h>
#include <memory>
#include <sstream>
#include <boost/format.hpp>


namespace fxcdm {

void
set_platform_api(const GMPPlatformAPI *api);

const GMPPlatformAPI *
get_platform_api();

GMPDecryptorCallback *
host();

class WidevineAdapter final : public GMPDecryptor
{
public:
    WidevineAdapter();

    virtual
    ~WidevineAdapter();

    virtual void
    Init(GMPDecryptorCallback *aCallback) override;

    virtual void
    CreateSession(uint32_t aCreateSessionToken, uint32_t aPromiseId, const char *aInitDataType,
                  uint32_t aInitDataTypeSize, const uint8_t *aInitData, uint32_t aInitDataSize,
                  GMPSessionType aSessionType) override;

    virtual void
    LoadSession(uint32_t aPromiseId, const char *aSessionId, uint32_t aSessionIdLength) override;

    virtual void
    UpdateSession(uint32_t aPromiseId, const char *aSessionId, uint32_t aSessionIdLength,
                  const uint8_t *aResponse, uint32_t aResponseSize) override;

    virtual void
    CloseSession(uint32_t aPromiseId, const char* aSessionId, uint32_t aSessionIdLength) override;

    virtual void
    RemoveSession(uint32_t aPromiseId, const char* aSessionId, uint32_t aSessionIdLength) override;

    virtual void
    SetServerCertificate(uint32_t aPromiseId, const uint8_t *aServerCert, uint32_t aServerCertSize)
                         override;

    virtual void
    Decrypt(GMPBuffer* aBuffer, GMPEncryptedBufferMetadata *aMetadata) override;

    virtual void
    DecryptingComplete() override;

private:
    struct Impl;
    std::unique_ptr<Impl> priv;
};

class WidevineAdapterAsyncShutdown final : public GMPAsyncShutdown
{
public:
    explicit WidevineAdapterAsyncShutdown(GMPAsyncShutdownHost *host_api);

    ~WidevineAdapterAsyncShutdown();

    void
    BeginShutdown() override;

private:
    GMPAsyncShutdownHost *host_api_;
};

inline std::string
to_hex_string(const uint8_t *data, uint32_t len)
{
    std::stringstream s;

    for (uint32_t k = 0; k < len; k ++) {
        if (k > 0)
            s << " ";
        s << boost::format("%02x") % static_cast<unsigned>(data[k]);
    }

    return s.str();
}

inline std::string
subsamples_to_string(uint32_t num, const uint16_t *clear, const uint32_t *cipher)
{
    std::stringstream s;

    for (uint32_t k = 0; k < num; k ++) {
        if (k > 0)
            s << " ";

        s << boost::format("(%1%, %2%)") % clear[k] % cipher[k];
    }

    return s.str();
}

} // namespace fxcdm
