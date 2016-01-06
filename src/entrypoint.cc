#include <iostream>
#include <string>
#include <gmp-errors.h>
#include <gmp-platform.h>
#include <gmp-decryption.h>
#include <gmp-async-shutdown.h>
#include <boost/format.hpp>


using std::cout;
using std::string;
using boost::format;


const GMPPlatformAPI *platform_api = nullptr;


class WidevineAdapter final : public GMPDecryptor
{
public:
    virtual void
    Init(GMPDecryptorCallback *aCallback) override
    {
        cout << format("WidevineAdapter::Init aCallback=%1%\n") % aCallback;
        decryptor_cb_ = aCallback;
        decryptor_cb_->SetCapabilities(GMP_EME_CAP_DECRYPT_AUDIO | GMP_EME_CAP_DECRYPT_VIDEO);
    }

    virtual void
    CreateSession(uint32_t aCreateSessionToken, uint32_t aPromiseId, const char *aInitDataType,
                  uint32_t aInitDataTypeSize, const uint8_t *aInitData, uint32_t aInitDataSize,
                  GMPSessionType aSessionType) override
    {
        cout << format("WidevineAdapter::CreateSession aCreateSessionToken=%u, aPromiseId=%u, "
                "aInitDataType=%s, aInitDataTypeSize=%u, aInitData=%p, aInitDataSize=%u, "
                "aSessionType=%u\n") % aCreateSessionToken % aPromiseId % aInitDataType %
                aInitDataTypeSize % aInitData % aInitDataSize % aSessionType;

        string session_id {"hello, world"};
        decryptor_cb_->SetSessionId(aCreateSessionToken, session_id.c_str(), session_id.size());
        decryptor_cb_->ResolvePromise(aPromiseId);
    }

    virtual void
    LoadSession(uint32_t aPromiseId, const char *aSessionId, uint32_t aSessionIdLength) override
    {
        cout << "WidevineAdapter::LoadSession\n";
    }

    virtual void
    UpdateSession(uint32_t aPromiseId, const char *aSessionId, uint32_t aSessionIdLength,
                  const uint8_t *aResponse, uint32_t aResponseSize) override
    {
        cout << "WidevineAdapter::UpdateSession\n";
    }

    virtual void
    CloseSession(uint32_t aPromiseId, const char* aSessionId, uint32_t aSessionIdLength) override
    {
        cout << "WidevineAdapter::CloseSession\n";
    }

    virtual void
    RemoveSession(uint32_t aPromiseId, const char* aSessionId, uint32_t aSessionIdLength) override
    {
        cout << "WidevineAdapter::RemoveSession\n";
    }

    virtual void
    SetServerCertificate(uint32_t aPromiseId, const uint8_t *aServerCert, uint32_t aServerCertSize)
                         override
    {
        cout << "WidevineAdapter::SetServerCertificate\n";
    }

    virtual void
    Decrypt(GMPBuffer* aBuffer, GMPEncryptedBufferMetadata *aMetadata) override
    {
        cout << format("WidevineAdapter::Decrypt aBuffer=%p, aMetadata=%p\n") % aBuffer % aMetadata;
        cout << format("    aBuffer->Id() = %u, aBuffer->Size() = %u\n") % aBuffer->Id() %
                aBuffer->Size();
    }

    virtual void
    DecryptingComplete() override
    {
        cout << "WidevineAdapter::DecryptingComplete\n";
    }

private:
    GMPDecryptorCallback *decryptor_cb_ = nullptr;
};

class WidevineAdapterAsyncShutdown final : public GMPAsyncShutdown
{
public:
    explicit WidevineAdapterAsyncShutdown(GMPAsyncShutdownHost *host_api)
        : host_api_(host_api)
    {}

    void
    BeginShutdown() override
    {
        cout << "WidevineAdapterAsyncShutdown::BeginShutdown\n";
    }

    ~WidevineAdapterAsyncShutdown()
    {
        cout << "WidevineAdapterAsyncShutdown::~WidevineAdapterAsyncShutdown\n";
    }

private:
    GMPAsyncShutdownHost *host_api_;
};


extern "C"
GMPErr
GMPInit(const GMPPlatformAPI *aPlatformAPI)
{
    cout << format("%1% aPlatformAPI=%2%\n") % __func__ % aPlatformAPI;
    platform_api = aPlatformAPI;
    return GMPNoErr;
}

extern "C"
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

extern "C"
void
GMPShutdown(void)
{
    cout << format("%1%\n") % __func__;
}
