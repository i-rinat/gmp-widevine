#include <string>
#include <boost/format.hpp>
#include "firefoxcdm.hh"
#include "chromecdm.hh"
#include "log.hh"


namespace fxcdm {

using std::string;
using boost::format;

const GMPPlatformAPI *platform_api = nullptr;

struct WidevineAdapter::Impl {
    GMPDecryptorCallback           *decryptor_cb_ = nullptr;
    cdm::ContentDecryptionModule   *crcdm_ = nullptr;
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
    LOGD << format("fxcdm::WidevineAdapter::Init aCallback=%1%\n") % aCallback;
    priv->decryptor_cb_ = aCallback;
    priv->decryptor_cb_->SetCapabilities(GMP_EME_CAP_DECRYPT_AUDIO | GMP_EME_CAP_DECRYPT_VIDEO);
}

void
WidevineAdapter::CreateSession(uint32_t aCreateSessionToken, uint32_t aPromiseId,
                               const char *aInitDataType, uint32_t aInitDataTypeSize,
                               const uint8_t *aInitData, uint32_t aInitDataSize,
                               GMPSessionType aSessionType)
{
    LOGD << format("fxcdm::WidevineAdapter::CreateSession aCreateSessionToken=%u, aPromiseId=%u, "
            "aInitDataType=%s, aInitDataTypeSize=%u, aInitData=%p, aInitDataSize=%u, "
            "aSessionType=%u\n") % aCreateSessionToken % aPromiseId % aInitDataType %
            aInitDataTypeSize % aInitData % aInitDataSize % aSessionType;

    if (!priv->decryptor_cb_) {
        LOGD << "   no decryptor_cb_ yet\n";
        return;
    }

    string session_id {"hello, world"};
    priv->decryptor_cb_->SetSessionId(aCreateSessionToken, session_id.c_str(), session_id.size());
    priv->decryptor_cb_->ResolvePromise(aPromiseId);

    priv->crcdm_ = crcdm::CreateInstance();
    if (!priv->crcdm_) {
        LOGD << "   failed to create cdm::ContentDecryptionModule instance\n";
        return;
    }

    priv->crcdm_->Initialize(true, true); // TODO: allow_distinctive_identifier?

    string init_data_type_str {aInitDataType, aInitDataTypeSize};
    enum cdm::InitDataType init_data_type = cdm::kCenc;

    if (init_data_type_str == "cenc") {
        init_data_type = cdm::kCenc;
    } else if (init_data_type_str == "keyids") {
        init_data_type = cdm::kKeyIds;
    } else if (init_data_type_str == "webm") {
        init_data_type = cdm::kWebM;
    } else {
        LOGD << "   unknown init data type '" << init_data_type_str << "'\n";
    }

    priv->crcdm_->CreateSessionAndGenerateRequest(
                        aPromiseId,
                        aSessionType == kGMPPersistentSession ? cdm::kPersistentLicense
                                                              : cdm::kTemporary,
                        init_data_type, aInitData, aInitDataSize);
}

void
WidevineAdapter::LoadSession(uint32_t aPromiseId, const char *aSessionId, uint32_t aSessionIdLength)
{
    LOGD << "fxcdm::WidevineAdapter::LoadSession\n";
}

void
WidevineAdapter::UpdateSession(uint32_t aPromiseId, const char *aSessionId,
                               uint32_t aSessionIdLength, const uint8_t *aResponse,
                               uint32_t aResponseSize)
{
    LOGD << "fxcdm::WidevineAdapter::UpdateSession\n";
}

void
WidevineAdapter::CloseSession(uint32_t aPromiseId, const char *aSessionId,
                              uint32_t aSessionIdLength)
{
    LOGD << "fxcdm::WidevineAdapter::CloseSession\n";
}

void
WidevineAdapter::RemoveSession(uint32_t aPromiseId, const char *aSessionId,
                               uint32_t aSessionIdLength)
{
    LOGD << "fxcdm::WidevineAdapter::RemoveSession\n";
}

void
WidevineAdapter::SetServerCertificate(uint32_t aPromiseId, const uint8_t *aServerCert,
                                      uint32_t aServerCertSize)
{
    LOGD << "fxcdm::WidevineAdapter::SetServerCertificate\n";
}

void
WidevineAdapter::Decrypt(GMPBuffer *aBuffer, GMPEncryptedBufferMetadata *aMetadata)
{
    LOGD << format("fxcdm::WidevineAdapter::Decrypt aBuffer=%p, aMetadata=%p\n") % aBuffer %
            aMetadata;
    LOGD << format("    aBuffer->Id() = %u, aBuffer->Size() = %u\n") % aBuffer->Id() %
            aBuffer->Size();
}

void
WidevineAdapter::DecryptingComplete()
{
    LOGD << "fxcdm::WidevineAdapter::DecryptingComplete\n";
}


WidevineAdapterAsyncShutdown::WidevineAdapterAsyncShutdown(GMPAsyncShutdownHost *host_api)
    : host_api_(host_api)
{
}

void
WidevineAdapterAsyncShutdown::BeginShutdown()
{
    LOGD << "fxcdm::WidevineAdapterAsyncShutdown::BeginShutdown\n";
}

WidevineAdapterAsyncShutdown::~WidevineAdapterAsyncShutdown()
{
    LOGD << "fxcdm::WidevineAdapterAsyncShutdown::~WidevineAdapterAsyncShutdown\n";
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
