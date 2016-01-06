#include <iostream>
#include <string>
#include <boost/format.hpp>
#include "firefoxcdm.hh"


namespace fxcdm {

using std::cout;
using std::string;
using boost::format;

const GMPPlatformAPI *platform_api = nullptr;

void
WidevineAdapter::Init(GMPDecryptorCallback *aCallback)
{
    cout << format("WidevineAdapter::Init aCallback=%1%\n") % aCallback;
    decryptor_cb_ = aCallback;
    decryptor_cb_->SetCapabilities(GMP_EME_CAP_DECRYPT_AUDIO | GMP_EME_CAP_DECRYPT_VIDEO);
}

void
WidevineAdapter::CreateSession(uint32_t aCreateSessionToken, uint32_t aPromiseId,
                               const char *aInitDataType, uint32_t aInitDataTypeSize,
                               const uint8_t *aInitData, uint32_t aInitDataSize,
                               GMPSessionType aSessionType)
{
    cout << format("WidevineAdapter::CreateSession aCreateSessionToken=%u, aPromiseId=%u, "
            "aInitDataType=%s, aInitDataTypeSize=%u, aInitData=%p, aInitDataSize=%u, "
            "aSessionType=%u\n") % aCreateSessionToken % aPromiseId % aInitDataType %
            aInitDataTypeSize % aInitData % aInitDataSize % aSessionType;

    string session_id {"hello, world"};
    decryptor_cb_->SetSessionId(aCreateSessionToken, session_id.c_str(), session_id.size());
    decryptor_cb_->ResolvePromise(aPromiseId);
}

void
WidevineAdapter::LoadSession(uint32_t aPromiseId, const char *aSessionId, uint32_t aSessionIdLength)
{
    cout << "WidevineAdapter::LoadSession\n";
}

void
WidevineAdapter::UpdateSession(uint32_t aPromiseId, const char *aSessionId,
                               uint32_t aSessionIdLength, const uint8_t *aResponse,
                               uint32_t aResponseSize)
{
    cout << "WidevineAdapter::UpdateSession\n";
}

void
WidevineAdapter::CloseSession(uint32_t aPromiseId, const char *aSessionId,
                              uint32_t aSessionIdLength)
{
    cout << "WidevineAdapter::CloseSession\n";
}

void
WidevineAdapter::RemoveSession(uint32_t aPromiseId, const char *aSessionId,
                               uint32_t aSessionIdLength)
{
    cout << "WidevineAdapter::RemoveSession\n";
}

void
WidevineAdapter::SetServerCertificate(uint32_t aPromiseId, const uint8_t *aServerCert,
                                      uint32_t aServerCertSize)
{
    cout << "WidevineAdapter::SetServerCertificate\n";
}

void
WidevineAdapter::Decrypt(GMPBuffer *aBuffer, GMPEncryptedBufferMetadata *aMetadata)
{
    cout << format("WidevineAdapter::Decrypt aBuffer=%p, aMetadata=%p\n") % aBuffer % aMetadata;
    cout << format("    aBuffer->Id() = %u, aBuffer->Size() = %u\n") % aBuffer->Id() %
            aBuffer->Size();
}

void
WidevineAdapter::DecryptingComplete()
{
    cout << "WidevineAdapter::DecryptingComplete\n";
}


WidevineAdapterAsyncShutdown::WidevineAdapterAsyncShutdown(GMPAsyncShutdownHost *host_api)
    : host_api_(host_api)
{
}

void
WidevineAdapterAsyncShutdown::BeginShutdown()
{
    cout << "WidevineAdapterAsyncShutdown::BeginShutdown\n";
}

WidevineAdapterAsyncShutdown::~WidevineAdapterAsyncShutdown()
{
    cout << "WidevineAdapterAsyncShutdown::~WidevineAdapterAsyncShutdown\n";
}

void
set_platform_api(const GMPPlatformAPI *api)
{
    platform_api = api;
}

} // namespace fxcdm
