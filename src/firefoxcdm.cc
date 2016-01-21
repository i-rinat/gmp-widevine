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
#include <arpa/inet.h>
#include <lib/gmp-task-utils.h>
#include <lib/AnnexB.h>


namespace fxcdm {

using boost::format;
using std::string;
using std::stringstream;
using std::vector;
using std::shared_ptr;
using std::make_shared;


const GMPPlatformAPI *platform_api = nullptr;
GMPDecryptorCallback *host_interface = nullptr;

GMPDecryptorCallback *
host()
{
    return host_interface;
}

GMPErr
to_GMPErr(cdm::Status status)
{
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

    ~DecryptedBlockImpl()
    {
        if (buffer_)
            buffer_->Destroy();
    }

private:
    int64_t      timestamp_ = 0;
    cdm::Buffer *buffer_    = nullptr;
};


Module::Module()
{
    AddRef();
}

Module::~Module()
{
}

void
Module::Init(GMPDecryptorCallback *aCallback)
{
    LOGF << format("fxcdm::Module::Init aCallback=%1%\n") % aCallback;
    host_interface = aCallback;
    fxcdm::host()->SetCapabilities(GMP_EME_CAP_DECRYPT_AUDIO |
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

    // TODO: error handling
    fxcdm::host()->Decrypted(aBuffer, to_GMPErr(decode_status));
}

void
Module::DecryptingComplete()
{
    LOGF << "fxcdm::Module::DecryptingComplete (void)\n";

    crcdm::Deinitialize();

    Release();
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

        vector<uint8_t> extra_data{aCodecSpecific + 1, aCodecSpecific + aCodecSpecificLength};

        AnnexB::ConvertConfig(extra_data, extra_data_annexb_);

        video_decoder_config.extra_data = nullptr;
        video_decoder_config.extra_data_size = 0;

        break;
    }

    // TODO: call on worker thread
    cdm::Status status = crcdm::get()->InitializeVideoDecoder(video_decoder_config);

    LOGF << format("   InitializeVideoDecoder() returned %1%\n") % status;
}

void
VideoDecoder::Decode(GMPVideoEncodedFrame *aInputFrame, bool aMissingFrames,
                     const uint8_t *aCodecSpecificInfo, uint32_t aCodecSpecificInfoLength,
                     int64_t aRenderTimeMs)
{
    LOGF << format("fxcdm::VideoDecoder::Decode aInputFrame=%1%, aMissingFrames=%2%, "
            "aCodecSpecificInfo=%3%, aCodecSpecificInfoLength=%4%, aRenderTimeMs=%5%\n") %
            aInputFrame % aMissingFrames % static_cast<const void *>(aCodecSpecificInfo) %
            aCodecSpecificInfoLength % aRenderTimeMs;

    LOGF << format("   data = %1%, data_size = %2%\n") %
            static_cast<const void *>(aInputFrame->Buffer()) % aInputFrame->Size();

    LOGF << format("   BufferType() = %1%\n") % aInputFrame->BufferType();

    auto ddata = make_shared<DecodeData>();

    ddata->buf_type = aInputFrame->BufferType();
    ddata->buf.assign(aInputFrame->Buffer(), aInputFrame->Buffer() + aInputFrame->Size());

    ddata->is_key_frame = (aInputFrame->FrameType() == kGMPKeyFrame);

    const GMPEncryptedBufferMetadata *metadata = aInputFrame->GetDecryptionData();
    LOGF << format("   metadata = %1%\n") % static_cast<const void *>(metadata);

    if (metadata) {
        ddata->key_id.assign(metadata->KeyId(), metadata->KeyId() + metadata->KeyIdSize());
        ddata->iv.assign(metadata->IV(), metadata->IV() + metadata->IVSize());

        LOGF << format("   key = %1%\n") % to_hex_string(metadata->KeyId(), metadata->KeyIdSize());
        LOGF << format("   IV = %1%\n") % to_hex_string(metadata->IV(), metadata->IVSize());
        LOGF << format("   subsamples (clear, cipher) = %1%\n") %
            subsamples_to_string(metadata->NumSubsamples(), metadata->ClearBytes(),
                                 metadata->CipherBytes());
        LOGF << format("   timestamp = %1%\n") % aInputFrame->TimeStamp();

        for (uint32_t k = 0; k < metadata->NumSubsamples(); k ++)
            ddata->subsamples.emplace_back(metadata->ClearBytes()[k], metadata->CipherBytes()[k]);
    }

    ddata->timestamp = aInputFrame->TimeStamp();
    ddata->duration = aInputFrame->Duration();

    aInputFrame->Destroy();

    EnsureWorkerIsRunning();
    worker_thread_->Post(WrapTaskRefCounted(this, &VideoDecoder::DecodeTask, ddata));
}

void
VideoDecoder::DecodeTask(shared_ptr<DecodeData> ddata)
{
    LOGF << format("fxcdm::VideoDecoder::DecodeTask ddata=%1%\n") % ddata.get();

    if (ddata->buf_type != 4) {
        // works only for buffer type 4, but comments in Firefox say that Gecko shouldn't
        // generate buffers of other types
        LOGZ << "   BufferType() != 4 are not implemented\n";
        return;
    }

    AnnexB::ConvertFrameInPlace(ddata->buf);

    if (ddata->is_key_frame) {
        LOGF << "   is a key frame\n";
        // insert extra data
        ddata->buf.insert(ddata->buf.begin(), extra_data_annexb_.begin(), extra_data_annexb_.end());
        LOGF << format("   new data size = %1%\n") % ddata->buf.size();

        // update subsample information, if any
        if (ddata->subsamples.size() > 0) {
            ddata->subsamples[0].clear_bytes += extra_data_annexb_.size();
        }

        std::stringstream s;
        for (auto k: ddata->subsamples)
            s << format(" (%1%, %2%)") % k.clear_bytes % k.cipher_bytes;
        LOGF << format("   subsamples =%1%\n") % s.str();
    }

    cdm::InputBuffer inp_buf;

    inp_buf.data =        ddata->buf.data();
    inp_buf.data_size =   ddata->buf.size();

    inp_buf.key_id =      ddata->key_id.data();
    inp_buf.key_id_size = ddata->key_id.size();

    inp_buf.iv =          ddata->iv.data();
    inp_buf.iv_size =     ddata->iv.size();

    inp_buf.subsamples =     ddata->subsamples.data();
    inp_buf.num_subsamples = ddata->subsamples.size();

    inp_buf.timestamp = ddata->timestamp;

    auto crvf = make_shared<crcdm::VideoFrame>();
    cdm::Status status = crcdm::get()->DecryptAndDecodeFrame(inp_buf, crvf.get());
    LOGF << format("   DecryptAndDecodeFrame returned %1%\n") % status;

    if (status == cdm::kNeedMoreData) {

        LOGF << "   scheduling dec_cb_->InputDataExhausted()\n";
        fxcdm::get_platform_api()->runonmainthread(
            WrapTask(dec_cb_, &GMPVideoDecoderCallback::InputDataExhausted));

    } else if (status == cdm::kSuccess) {

        LOGF << "   scheduling DecodedTaskCallDecoded\n";

        shared_ptr<vector<uint8_t>> raw(new vector<uint8_t>);
        cdm::Size sz = crvf->Size();
        auto crbuf = crvf->FrameBuffer();
        raw->assign(crbuf->Data(), crbuf->Data() + crbuf->Size());

        uint32_t y_stride = crvf->Stride(cdm::VideoFrame::kYPlane);
        uint32_t u_stride = crvf->Stride(cdm::VideoFrame::kUPlane);
        uint32_t v_stride = crvf->Stride(cdm::VideoFrame::kVPlane);

        // uint32_t y_offset = crvf->PlaneOffset(cdm::VideoFrame::kYPlane);
        // uint32_t u_offset = crvf->PlaneOffset(cdm::VideoFrame::kUPlane);
        // uint32_t v_offset = crvf->PlaneOffset(cdm::VideoFrame::kVPlane);

        // TODO: why widevine provides invalid offsets?

        uint32_t y_offset = 0;
        uint32_t u_offset = y_offset + y_stride * sz.height;
        uint32_t v_offset = u_offset + u_stride * sz.height / 2;

        crvf->FrameBuffer()->Destroy();

        fxcdm::get_platform_api()->runonmainthread(
            WrapTaskRefCounted(this, &VideoDecoder::DecodedTaskCallDecoded, raw, sz, y_offset,
                               u_offset, v_offset, y_stride, u_stride, v_stride, ddata->timestamp,
                               ddata->duration));

    } else {
        LOGZ << "   failure\n";
        fxcdm::get_platform_api()->runonmainthread(
            WrapTask(dec_cb_, &GMPVideoDecoderCallback::Error, to_GMPErr(status)));
    }
}

void
VideoDecoder::DecodedTaskCallDecoded(shared_ptr<vector<uint8_t>> raw, cdm::Size sz,
                                     uint32_t y_offset, uint32_t u_offset, uint32_t v_offset,
                                     uint32_t y_stride, uint32_t u_stride, uint32_t v_stride,
                                     uint64_t timestamp, uint64_t duration)
{
    LOGF << format("fxcdm::VideoDecoder::DecodedTaskCallDecoded raw.size()=%1%, sz={.width=%2%, "
            ".height=%3%}, y_offset=%4%, u_offset=%5%, v_offset=%6%, y_stride=%7%, u_stride=%8%, "
            "v_stride=%9%, timestamp=%10%, duration=%11%\n") % raw->size() % sz.width % sz.height %
            y_offset % u_offset % v_offset % y_stride % u_stride % v_stride % timestamp % duration;

    GMPVideoFrame *fxvf = nullptr;
    auto err = host_api_->CreateFrame(kGMPI420VideoFrame, &fxvf);
    if (GMP_FAILED(err)) {
        LOGZ << format("   CreateFrame failed with code %1%\n") % err;
        return;
    }

    auto fxvf_i420 = static_cast<GMPVideoi420Frame *>(fxvf);
    fxvf_i420->CreateFrame(y_stride * sz.height,     raw->data() + y_offset,
                           u_stride * sz.height / 2, raw->data() + u_offset,
                           v_stride * sz.height / 2, raw->data() + v_offset,
                           sz.width, sz.height,
                           y_stride, u_stride, v_stride);

    fxvf_i420->SetTimestamp(timestamp);
    fxvf_i420->SetDuration(duration);

    dec_cb_->Decoded(fxvf_i420);
    dec_cb_->InputDataExhausted();
    LOGF << "   called dec_cb_->Decoded()\n";
}

void
VideoDecoder::EnsureWorkerIsRunning()
{
    LOGF << "fxcdm::VideoDecoder::EnsureWorkerIsRunning (void)\n";

    if (worker_thread_)
        return;

    fxcdm::get_platform_api()->createthread(&worker_thread_);
    if (!worker_thread_) {
        LOGZ << "   failed to create worker thread\n";
        dec_cb_->Error(GMPAllocErr);
    }
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
    LOGF << "fxcdm::VideoDecoder::Drain (void)\n";
    // chrome interface doesn't have Drain() equivalent.
    // Since ResetDecoder() should also flush buffers, maybe it would suffice?
    crcdm::get()->ResetDecoder(cdm::kStreamTypeVideo);
    dec_cb_->DrainComplete();
}

void
VideoDecoder::DecodingComplete()
{
    LOGF << "fxcdm::VideoDecoder::DecodingComplete (void)\n";

    if (worker_thread_) {
        worker_thread_->Join();
        worker_thread_ = nullptr;
    }

    crcdm::get()->DeinitializeDecoder(cdm::kStreamTypeVideo);

    Release();
}

string
GMPAudioCodec_to_string(const GMPAudioCodec &a)
{
    std::stringstream s;

    s << format("{.mCodecType=%1%, .mChannelCount=%2%, .mBitsPerChannel=%3%, "
         ".mSamplesPerSecond=%4%, .mExtraData=%5%, .mExtraDataLen=%6%}") % a.mCodecType %
         a.mChannelCount % a.mBitsPerChannel % a.mSamplesPerSecond %
         static_cast<const void *>(a.mExtraData) % a.mExtraDataLen;

    return s.str();
}

void
AudioDecoder::InitDecode(const GMPAudioCodec &aCodecSettings,
                         GMPAudioDecoderCallback *aCallback)
{
    LOGF << format("fxcdm::AudioDecoder::InitDecode aCodecSettings=%1%, aCallback=%2%\n") %
            GMPAudioCodec_to_string(aCodecSettings) % aCallback;

    dec_cb_ = aCallback;

    cdm::AudioDecoderConfig aconf;

    switch (aCodecSettings.mCodecType) {
    case kGMPAudioCodecAAC:

        aconf.codec = cdm::AudioDecoderConfig::kCodecAac;
        aconf.channel_count = aCodecSettings.mChannelCount;
        aconf.bits_per_channel = aCodecSettings.mBitsPerChannel;
        aconf.samples_per_second = aCodecSettings.mSamplesPerSecond;
        aconf.extra_data = const_cast<uint8_t *>(aCodecSettings.mExtraData); // TODO: copy if called
                                                                             // on another thread
        aconf.extra_data_size = aCodecSettings.mExtraDataLen;

        break;

    case kGMPAudioCodecVorbis:
    default:

        LOGZ << "   audio codec not implemented\n";
        break;
    }

    // TODO: call on worker thread
    cdm::Status status = crcdm::get()->InitializeAudioDecoder(aconf);

    LOGF << format("   InitializeAudioDecoder() returned %1%\n") % status;
}

void
AudioDecoder::Decode(GMPAudioSamples *aEncodedSamples)
{
    LOGZ << format("fxcdm::AudioDecoder::Decode aEncodedSamples=%1%\n") % aEncodedSamples;
}

void
AudioDecoder::Reset()
{
    LOGZ << "fxcdm::AudioDecoder::Reset (void)\n";
}

void
AudioDecoder::Drain()
{
    LOGZ << "fxcdm::AudioDecoder::Drain (void)\n";
}

void
AudioDecoder::DecodingComplete()
{
    LOGZ << "fxcdm::AudioDecoder::DecodingComplete (void)\n";
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
