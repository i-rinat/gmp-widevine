#pragma once

#include <gmp/gmp-decryption.h>
#include <gmp/gmp-async-shutdown.h>
#include <memory>


namespace fxcdm {

void
set_platform_api(const GMPPlatformAPI *api);

const GMPPlatformAPI *
get_platform_api();

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

} // namespace fxcdm
