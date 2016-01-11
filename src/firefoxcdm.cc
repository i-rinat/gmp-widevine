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
#include <vector>
#include <string.h>
#include "firefoxcdm.hh"
#include "chromecdm.hh"
#include "log.hh"


namespace fxcdm {

using boost::format;
using std::string;
using std::stringstream;
using std::vector;


const GMPPlatformAPI *platform_api = nullptr;
GMPDecryptorCallback *host_interface = nullptr;

GMPDecryptorCallback *
host()
{
    return host_interface;
}

class DecryptedBlockImpl final : public cdm::DecryptedBlock
{
public:
   virtual void
   SetDecryptedBuffer(cdm::Buffer *buffer) override
   {
       LOGF << format("fxcdm::DecryptedBlockImpl::SetDecryptedBuffer buffer=%p\n") % buffer;
       buffer_ = buffer;
   }

   virtual cdm::Buffer *
   DecryptedBuffer() override
   {
       LOGF << "fxcdm::DecryptedBlockImpl::DecryptedBuffer (void)\n";
       return buffer_;
   }

   virtual void
   SetTimestamp(int64_t timestamp) override
   {
       LOGF << format("fxcdm::DecryptedBlockImpl::SetTimestamp timestamp=%1%\n") % timestamp;
       timestamp_ = timestamp;
   }

   virtual int64_t
   Timestamp() const override
   {
       LOGF << "fxcdm::DecryptedBlockImpl::Timestamp (void)\n";
       return timestamp_;
   }

private:
    int64_t      timestamp_ = 0;
    cdm::Buffer *buffer_    = nullptr;
};


Module::Module()
{
}

Module::~Module()
{
}

void
Module::Init(GMPDecryptorCallback *aCallback)
{
    LOGF << format("fxcdm::Module::Init aCallback=%1%\n") % aCallback;
    host_interface = aCallback;
    fxcdm::host()->SetCapabilities(GMP_EME_CAP_DECRYPT_AND_DECODE_AUDIO |
                                   GMP_EME_CAP_DECRYPT_AND_DECODE_VIDEO);

    crcdm::Initialize();
}

void
Module::CreateSession(uint32_t aCreateSessionToken, uint32_t aPromiseId, const char *aInitDataType,
                      uint32_t aInitDataTypeSize, const uint8_t *aInitData, uint32_t aInitDataSize,
                      GMPSessionType aSessionType)
{
    LOGF << format("fxcdm::Module::CreateSession aCreateSessionToken=%u, aPromiseId=%u, "
            "aInitDataType=%s, aInitDataTypeSize=%u, aInitData=%p, aInitDataSize=%u, "
            "aSessionType=%u\n") % aCreateSessionToken % aPromiseId % aInitDataType %
            aInitDataTypeSize % static_cast<const void *>(aInitData) % aInitDataSize % aSessionType;

    if (!fxcdm::host()) {
        LOGZ << "   no decryptor_cb_ yet\n";
        return;
    }

    string init_data_type_str {aInitDataType, aInitDataTypeSize};
    enum cdm::InitDataType init_data_type = cdm::kCenc;

    if (init_data_type_str == "cenc") {
        init_data_type = cdm::kCenc;
    } else if (init_data_type_str == "keyids") {
        init_data_type = cdm::kKeyIds;
    } else if (init_data_type_str == "webm") {
        init_data_type = cdm::kWebM;
    } else {
        LOGZ << "   unknown init data type '" << init_data_type_str << "'\n";
    }

    crcdm::set_create_session_token(aCreateSessionToken);
    crcdm::get()->CreateSessionAndGenerateRequest(
                        aPromiseId,
                        aSessionType == kGMPPersistentSession ? cdm::kPersistentLicense
                                                              : cdm::kTemporary,
                        init_data_type, aInitData, aInitDataSize);
}

void
Module::LoadSession(uint32_t aPromiseId, const char *aSessionId, uint32_t aSessionIdLength)
{
    LOGZ << "fxcdm::Module::LoadSession\n";
}

void
Module::UpdateSession(uint32_t aPromiseId, const char *aSessionId, uint32_t aSessionIdLength,
                      const uint8_t *aResponse, uint32_t aResponseSize)
{
    LOGF << format("fxcdm::Module::UpdateSession aPromiseId=%1%, aSessionId=%2%, "
            "aSessionIdLength=%3%, aResponse=%4%, aResponseSize=%5%\n") % aPromiseId %
            string(aSessionId, aSessionIdLength) % aSessionIdLength %
            static_cast<const void *>(aResponse) % aResponseSize;

    crcdm::get()->UpdateSession(aPromiseId, aSessionId, aSessionIdLength, aResponse, aResponseSize);
}

void
Module::CloseSession(uint32_t aPromiseId, const char *aSessionId, uint32_t aSessionIdLength)
{
    LOGF << format("fxcdm::Module::CloseSession aPromiseId=%1%, aSessionId=%2%, "
            "aSessionIdLength=%3%\n") % aPromiseId % string(aSessionId, aSessionIdLength) %
            aSessionIdLength;

    crcdm::get()->CloseSession(aPromiseId, aSessionId, aSessionIdLength);
}

void
Module::RemoveSession(uint32_t aPromiseId, const char *aSessionId, uint32_t aSessionIdLength)
{
    LOGZ << "fxcdm::Module::RemoveSession\n";
}

void
Module::SetServerCertificate(uint32_t aPromiseId, const uint8_t *aServerCert,
                             uint32_t aServerCertSize)
{
    LOGZ << "fxcdm::Module::SetServerCertificate\n";
}

void
Module::Decrypt(GMPBuffer *aBuffer, GMPEncryptedBufferMetadata *aMetadata)
{
    LOGF << format("fxcdm::Module::Decrypt aBuffer=%p, aMetadata=%p\n") % aBuffer %
            aMetadata;
    LOGF << format("   aBuffer->Id() = %u, aBuffer->Size() = %u\n") % aBuffer->Id() %
            aBuffer->Size();

    cdm::InputBuffer    encrypted_buffer;

    encrypted_buffer.data =      aBuffer->Data();
    encrypted_buffer.data_size = aBuffer->Size();

    encrypted_buffer.key_id =      aMetadata->KeyId();
    encrypted_buffer.key_id_size = aMetadata->KeyIdSize();

    encrypted_buffer.iv =      aMetadata->IV();
    encrypted_buffer.iv_size = aMetadata->IVSize();

    encrypted_buffer.num_subsamples = aMetadata->NumSubsamples();
    vector<cdm::SubsampleEntry> subsamples;

    LOGF << format("   key = %1%\n") % to_hex_string(aMetadata->KeyId(), aMetadata->KeyIdSize());
    LOGF << format("   IV = %1%\n") % to_hex_string(aMetadata->IV(), aMetadata->IVSize());
    LOGF << format("   subsamples (clear, cipher) = %1%\n") %
            subsamples_to_string(aMetadata->NumSubsamples(), aMetadata->ClearBytes(),
                                 aMetadata->CipherBytes());

    for (uint32_t k = 0; k < encrypted_buffer.num_subsamples; k ++)
        subsamples.emplace_back(aMetadata->ClearBytes()[k], aMetadata->CipherBytes()[k]);

    encrypted_buffer.subsamples = &subsamples[0];

    platform_api->getcurrenttime(&encrypted_buffer.timestamp);
    encrypted_buffer.timestamp *= 1000;

    DecryptedBlockImpl decrypted_block;
    cdm::Status decode_status = crcdm::get()->Decrypt(encrypted_buffer, &decrypted_block);

    LOGF << "    decode_status = " << decode_status << "\n";

    if (decode_status == cdm::kSuccess) {
        auto decrypted_buffer = decrypted_block.DecryptedBuffer();

        aBuffer->Resize(decrypted_buffer->Size());
        memcpy(aBuffer->Data(), decrypted_buffer->Data(), decrypted_buffer->Size());

        // TODO: error handling
        fxcdm::host()->Decrypted(aBuffer, GMPNoErr);
        return;
    }

    auto to_GMPErr = [](cdm::Status status) {
        switch (status) {
        case cdm::kSuccess:         return GMPNoErr;
        case cdm::kNeedMoreData:    return GMPGenericErr;
        case cdm::kNoKey:           return GMPNoKeyErr;
        case cdm::kSessionError:    return GMPGenericErr;
        case cdm::kDecryptError:    return GMPCryptoErr;
        case cdm::kDecodeError:     return GMPDecodeErr;
        case cdm::kDeferredInitialization: return GMPGenericErr;
        default:                    return GMPGenericErr;
        }
    };

    // TODO: error handling
    fxcdm::host()->Decrypted(aBuffer, to_GMPErr(decode_status));
}

void
Module::DecryptingComplete()
{
    LOGF << "fxcdm::Module::DecryptingComplete (void)\n";

    crcdm::Deinitialize();

    delete this;
}


ModuleAsyncShutdown::ModuleAsyncShutdown(GMPAsyncShutdownHost *host_api)
    : host_api_(host_api)
{
}

void
ModuleAsyncShutdown::BeginShutdown()
{
    LOGF << "fxcdm::ModuleAsyncShutdown::BeginShutdown (void)\n";

    // there is nothing to close asynchronously
    host_api_->ShutdownComplete();
}

ModuleAsyncShutdown::~ModuleAsyncShutdown()
{
    LOGF << "fxcdm::ModuleAsyncShutdown::~ModuleAsyncShutdown (void)\n";
    // TODO: delete self?
}


string
GMPVideoCodec_to_string(const GMPVideoCodec &a)
{
    std::stringstream s;

    s << format("{.mGMPApiVersion=%1%, .mCodecType=%2%, .mPLName=%3%, .mPLType=%4%, .mWidth=%5%, "
         ".mHeight=%6%, .mStartBitrate=%7%, .mMaxBitrate=%8%, .mMinBitrate=%9%, .mMaxFramerate=%10%"
         ", .mFrameDroppingOn=%11%, .mKeyFrameInterval=%12%, .mQPMax=%13%, "
         ".mNumberOfSimulcastStreams=%14%, .mSimulcastStream={") % a.mGMPApiVersion % a.mCodecType %
         a.mPLName % a.mPLType % a.mWidth % a.mHeight % a.mStartBitrate % a.mMaxBitrate %
         a.mMinBitrate % a.mMaxFramerate % a.mFrameDroppingOn % a.mKeyFrameInterval % a.mQPMax %
         a.mNumberOfSimulcastStreams;

    for (uint32_t k = 0; k < a.mNumberOfSimulcastStreams; k ++) {
        const GMPSimulcastStream &b = a.mSimulcastStream[k];

        if (k > 0)
            s << ", ";

        s << format("{.mWidth=%1%, .mHeight=%2%, .mNumberOfTemporalLayers=%3%, .mMaxBitrate=%4%, "
             ".mTargetBitrate=%5%, .mMinBitrate=%6%, .mQPMax=%7%}") % b.mWidth % b.mHeight %
             b.mNumberOfTemporalLayers % b.mMaxBitrate % b.mTargetBitrate % b.mMinBitrate %
             b.mQPMax;
    }

    s << format("}, .mMode=%1%}") % a.mMode;

    return s.str();
}

void
VideoDecoder::InitDecode(const GMPVideoCodec &aCodecSettings, const uint8_t *aCodecSpecific,
                         uint32_t aCodecSpecificLength, GMPVideoDecoderCallback *aCallback,
                         int32_t aCoreCount)
{
    LOGF << format("fxcdm::VideoDecoder::InitDecode aCodecSettings=%1%, aCodecSpecific=%2%, "
            "aCodecSpecificLength=%3%, aCallback=%4%, aCoreCount=%5%\n") %
            GMPVideoCodec_to_string(aCodecSettings) % static_cast<const void *>(aCodecSpecific) %
            aCodecSpecificLength % aCallback % aCoreCount;

    dec_cb_ = aCallback;

    cdm::VideoDecoderConfig video_decoder_config;

    switch (aCodecSettings.mCodecType) {
    default:
    case kGMPVideoCodecVP8:
        LOGZ << "  not implemented\n";
        return;
        break;

    case kGMPVideoCodecH264:

        video_decoder_config.codec = cdm::VideoDecoderConfig::kCodecH264;
        video_decoder_config.profile = cdm::VideoDecoderConfig::kH264ProfileHigh; // TODO: ?
        video_decoder_config.format = cdm::kYv12; // TODO: ?
        video_decoder_config.coded_size.width = aCodecSettings.mWidth;
        video_decoder_config.coded_size.height = aCodecSettings.mHeight;

        video_decoder_config.extra_data = const_cast<uint8_t *>(aCodecSpecific) + 1;
        video_decoder_config.extra_data_size = aCodecSpecificLength - 1;

        break;
    }

    cdm::Status status = crcdm::get()->InitializeVideoDecoder(video_decoder_config);

    LOGF << format("   InitializeVideoDecoder() returned %1%\n") % status;
}

void
VideoDecoder::Decode(GMPVideoEncodedFrame *aInputFrame, bool aMissingFrames,
                     const uint8_t *aCodecSpecificInfo, uint32_t aCodecSpecificInfoLength,
                     int64_t aRenderTimeMs)
{
    LOGZ << "fxcdm::VideoDecoder::Decode\n";
}

void
VideoDecoder::Reset()
{
    LOGF << "fxcdm::VideoDecoder::Reset (void)\n";
    crcdm::get()->ResetDecoder(cdm::kStreamTypeVideo);
    dec_cb_->ResetComplete();
}

void
VideoDecoder::Drain()
{
    LOGZ << "fxcdm::VideoDecoder::Drain (void)\n";
}

void
VideoDecoder::DecodingComplete()
{
    LOGZ << "fxcdm::VideoDecoder::DecodingComplete (void)\n";
}


void
set_platform_api(const GMPPlatformAPI *api)
{
    platform_api = api;
}

const GMPPlatformAPI *
get_platform_api()
{
    return platform_api;
}

} // namespace fxcdm
