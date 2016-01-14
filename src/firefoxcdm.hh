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

#include <api/gmp/gmp-decryption.h>
#include <api/gmp/gmp-async-shutdown.h>
#include <api/gmp/gmp-video-decode.h>
#include <api/gmp/gmp-video-host.h>
#include <api/gmp/gmp-audio-decode.h>
#include <api/gmp/gmp-audio-host.h>
#include <api/crcdm/content_decryption_module.h>
#include <lib/RefCounted.h>
#include <memory>
#include <sstream>
#include <boost/format.hpp>
#include "chromecdm.hh"


namespace fxcdm {

void
set_platform_api(const GMPPlatformAPI *api);

const GMPPlatformAPI *
get_platform_api();

GMPDecryptorCallback *
host();

class Module final : public GMPDecryptor, public RefCounted
{
public:
    Module();

    virtual
    ~Module();

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
};

class ModuleAsyncShutdown final : public GMPAsyncShutdown
{
public:
    explicit ModuleAsyncShutdown(GMPAsyncShutdownHost *host_api);

    ~ModuleAsyncShutdown();

    void
    BeginShutdown() override;

private:
    GMPAsyncShutdownHost *host_api_;
};


class VideoDecoder final : public GMPVideoDecoder, public RefCounted
{
public:
    VideoDecoder(GMPVideoHost *host_api)
        : host_api_(host_api)
    { AddRef(); }

    virtual void
    InitDecode(const GMPVideoCodec &aCodecSettings, const uint8_t *aCodecSpecific,
               uint32_t aCodecSpecificLength, GMPVideoDecoderCallback *aCallback,
               int32_t aCoreCount) override;

    virtual void
    Decode(GMPVideoEncodedFrame *aInputFrame, bool aMissingFrames,
           const uint8_t *aCodecSpecificInfo, uint32_t aCodecSpecificInfoLength,
           int64_t aRenderTimeMs = -1) override;

    virtual void
    Reset() override;

    virtual void
    Drain() override;

    virtual void
    DecodingComplete() override;

private:

    struct DecodeData {
        DecodeData()
            : buf_type(GMP_BufferInvalid)
            , duration(0)
            , timestamp(0)
        {}

        cdm::InputBuffer     inp_buf;
        GMPBufferType        buf_type;
        std::vector<uint8_t> buf;
        uint64_t             duration;
        uint64_t             timestamp;
        std::vector<uint8_t> key_id;
        std::vector<uint8_t> iv;
        std::vector<cdm::SubsampleEntry> subsamples;
    };

    void
    EnsureWorkerIsRunning();

    void
    DecodeTask(std::shared_ptr<DecodeData> ddata);

    void
    DecodedTaskCallDecoded(std::shared_ptr<crcdm::VideoFrame> crvf, uint64_t timestamp,
                           uint64_t duration);


    GMPVideoDecoderCallback *dec_cb_ = nullptr;
    GMPVideoHost            *host_api_;

    GMPThread               *worker_thread_ = nullptr;
};


class AudioDecoder final : public GMPAudioDecoder, public RefCounted
{
public:
    AudioDecoder(GMPAudioHost *host_api)
        : host_api_(host_api)
    { AddRef(); }

    virtual void
    InitDecode(const GMPAudioCodec &aCodecSettings, GMPAudioDecoderCallback *aCallback) override;

    virtual void
    Decode(GMPAudioSamples *aEncodedSamples) override;

    virtual void
    Reset() override;

    virtual void
    Drain() override;

    virtual void
    DecodingComplete() override;

private:
    GMPAudioHost               *host_api_;
    GMPAudioDecoderCallback    *dec_cb_ = nullptr;;
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
