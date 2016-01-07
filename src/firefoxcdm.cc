#include <string>
#include <vector>
#include <boost/format.hpp>
#include <string.h>
#include "firefoxcdm.hh"
#include "chromecdm.hh"
#include "log.hh"


namespace fxcdm {

using std::string;
using std::vector;
using boost::format;


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


struct WidevineAdapter::Impl {
    int dummy;
};

WidevineAdapter::WidevineAdapter()
    : priv(new Impl)
{
}

WidevineAdapter::~WidevineAdapter()
{
}

void
WidevineAdapter::Init(GMPDecryptorCallback *aCallback)
{
    LOGF << format("fxcdm::WidevineAdapter::Init aCallback=%1%\n") % aCallback;
    host_interface = aCallback;
    fxcdm::host()->SetCapabilities(GMP_EME_CAP_DECRYPT_AUDIO | GMP_EME_CAP_DECRYPT_VIDEO);

    crcdm::Initialize();
}

void
WidevineAdapter::CreateSession(uint32_t aCreateSessionToken, uint32_t aPromiseId,
                               const char *aInitDataType, uint32_t aInitDataTypeSize,
                               const uint8_t *aInitData, uint32_t aInitDataSize,
                               GMPSessionType aSessionType)
{
    LOGF << format("fxcdm::WidevineAdapter::CreateSession aCreateSessionToken=%u, aPromiseId=%u, "
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
WidevineAdapter::LoadSession(uint32_t aPromiseId, const char *aSessionId, uint32_t aSessionIdLength)
{
    LOGZ << "fxcdm::WidevineAdapter::LoadSession\n";
}

void
WidevineAdapter::UpdateSession(uint32_t aPromiseId, const char *aSessionId,
                               uint32_t aSessionIdLength, const uint8_t *aResponse,
                               uint32_t aResponseSize)
{
    LOGF << format("fxcdm::WidevineAdapter::UpdateSession aPromiseId=%1%, aSessionId=%2%, "
            "aSessionIdLength=%3%, aResponse=%4%, aResponseSize=%5%\n") % aPromiseId %
            string(aSessionId, aSessionIdLength) % aSessionIdLength %
            static_cast<const void *>(aResponse) % aResponseSize;

    crcdm::get()->UpdateSession(aPromiseId, aSessionId, aSessionIdLength, aResponse, aResponseSize);
}

void
WidevineAdapter::CloseSession(uint32_t aPromiseId, const char *aSessionId,
                              uint32_t aSessionIdLength)
{
    LOGF << format("fxcdm::WidevineAdapter::CloseSession aPromiseId=%1%, aSessionId=%2%, "
            "aSessionIdLength=%3%\n") % aPromiseId % string(aSessionId, aSessionIdLength) %
            aSessionIdLength;

    crcdm::get()->CloseSession(aPromiseId, aSessionId, aSessionIdLength);
}

void
WidevineAdapter::RemoveSession(uint32_t aPromiseId, const char *aSessionId,
                               uint32_t aSessionIdLength)
{
    LOGZ << "fxcdm::WidevineAdapter::RemoveSession\n";
}

void
WidevineAdapter::SetServerCertificate(uint32_t aPromiseId, const uint8_t *aServerCert,
                                      uint32_t aServerCertSize)
{
    LOGZ << "fxcdm::WidevineAdapter::SetServerCertificate\n";
}

void
WidevineAdapter::Decrypt(GMPBuffer *aBuffer, GMPEncryptedBufferMetadata *aMetadata)
{
    LOGF << format("fxcdm::WidevineAdapter::Decrypt aBuffer=%p, aMetadata=%p\n") % aBuffer %
            aMetadata;
    LOGF << format("    aBuffer->Id() = %u, aBuffer->Size() = %u\n") % aBuffer->Id() %
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
WidevineAdapter::DecryptingComplete()
{
    LOGZ << "fxcdm::WidevineAdapter::DecryptingComplete (void)\n";
}


WidevineAdapterAsyncShutdown::WidevineAdapterAsyncShutdown(GMPAsyncShutdownHost *host_api)
    : host_api_(host_api)
{
}

void
WidevineAdapterAsyncShutdown::BeginShutdown()
{
    LOGZ << "fxcdm::WidevineAdapterAsyncShutdown::BeginShutdown (void)\n";
}

WidevineAdapterAsyncShutdown::~WidevineAdapterAsyncShutdown()
{
    LOGZ << "fxcdm::WidevineAdapterAsyncShutdown::~WidevineAdapterAsyncShutdown (void)\n";
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
