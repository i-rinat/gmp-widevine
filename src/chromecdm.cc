#include "chromecdm.hh"
#include "log.hh"
#include <string>
#include <boost/format.hpp>
#include <chrono>
#include "firefoxcdm.hh"


using std::string;
using boost::format;


namespace crcdm {

class BufferImpl final : public cdm::Buffer {
public:
    BufferImpl(uint32_t capacity) { SetSize(capacity); }

    virtual void
    Destroy() override { free(data_); data_ = nullptr; sz = 0; }

    virtual uint32_t
    Capacity() const override { return sz;}

    virtual uint8_t *
    Data() override { return data_; }

    virtual void
    SetSize(uint32_t size) override
    {
        data_ = static_cast<uint8_t *>(realloc(static_cast<void *>(data_), size));
    }

    virtual uint32_t
    Size() const { return sz; }

private:
    uint8_t *data_ = nullptr;
    uint32_t sz = 0;
};


class Host final: public cdm::ContentDecryptionModule::Host {
public:

    virtual cdm::Buffer *
    Allocate(uint32_t capacity) override
    {
        LOGF << "crcdm::Host::Allocate\n";
        return new BufferImpl(capacity);
    }

    virtual void
    SetTimer(int64_t delay_ms, void *context) override
    {
        LOGZ << "crcdm::Host::SetTimer\n";
    }

    virtual cdm::Time
    GetCurrentWallTime() override
    {
        LOGF << "crcdm::Host::GetCurrentWallTime (void)\n";

        int64_t milliseconds = 0;
        fxcdm::get_platform_api()->getcurrenttime(&milliseconds);

        return milliseconds / 1e3;
    }

    virtual void
    OnResolveNewSessionPromise(uint32_t promise_id, const char *session_id,
                               uint32_t session_id_size) override
    {
        LOGF << format("crcdm::Host::OnResolveNewSessionPromise promise_id=%1%, session_id=%2%\n")
                % promise_id % string(session_id, session_id_size);

        decryptor_cb_->SetSessionId(create_session_token_, session_id, session_id_size);
        decryptor_cb_->ResolveLoadSessionPromise(promise_id, true);
    }

    virtual void
    OnResolvePromise(uint32_t promise_id) override
    {
        LOGZ << "crcdm::Host::OnResolvePromise\n";
    }

    virtual void
    OnRejectPromise(uint32_t promise_id, cdm::Error error, uint32_t system_code,
                    const char *error_message, uint32_t error_message_size) override
    {
        LOGZ << "crcdm::Host::OnRejectPromise\n";
    }

    virtual void
    OnSessionMessage(const char *session_id, uint32_t session_id_size,
                     cdm::MessageType message_type, const char *message, uint32_t message_size,
                     const char *legacy_destination_url,
                     uint32_t legacy_destination_url_length) override
    {
        LOGF << format("crcdm::Host::OnSessionMessage session_id=%1%, message_type=%2%, "
                "message=%3%, message_size=%4%, legacy_destination_url=%5%\n") %
                string(session_id, session_id_size) % message_type %
                static_cast<const void *>(message) % message_size %
                string(legacy_destination_url, legacy_destination_url_length);

        auto convert_to_GMPSessionMessageType = [](cdm::MessageType message_type) {
            switch (message_type) {
            case cdm::kLicenseRequest: return kGMPLicenseRequest;
            case cdm::kLicenseRenewal: return kGMPLicenseRenewal;
            case cdm::kLicenseRelease: return kGMPLicenseRelease;
            default:                   return kGMPMessageInvalid;
            };
        };

        decryptor_cb_->SessionMessage(session_id, session_id_size,
                                      convert_to_GMPSessionMessageType(message_type),
                                      reinterpret_cast<const uint8_t *>(message), message_size);
    }

    virtual void
    OnSessionKeysChange(const char *session_id, uint32_t session_id_size,
                        bool has_additional_usable_key, const cdm::KeyInformation *keys_info,
                        uint32_t keys_info_count) override
    {
        LOGZ << "crcdm::Host::OnSessionKeysChange\n";
    }

    virtual void
    OnExpirationChange(const char *session_id, uint32_t session_id_size,
                       cdm::Time new_expiry_time) override
    {
        LOGZ << "crcdm::Host::OnExpirationChange\n";
    }

    virtual void
    OnSessionClosed(const char *session_id, uint32_t session_id_size) override
    {
        LOGZ << "crcdm::Host::OnSessionClosed\n";
    }

    virtual void
    OnLegacySessionError(const char *session_id, uint32_t session_id_length, cdm::Error error,
                         uint32_t system_code, const char *error_message,
                         uint32_t error_message_length) override
    {
        LOGZ << "crcdm::Host::OnLegacySessionError\n";
    }

    virtual void
    SendPlatformChallenge(const char *service_id, uint32_t service_id_size, const char *challenge,
                          uint32_t challenge_size) override
    {
        LOGZ << "crcdm::Host::SendPlatformChallenge\n";
    }

    virtual void
    EnableOutputProtection(uint32_t desired_protection_mask) override
    {
        LOGZ << "crcdm::Host::EnableOutputProtection\n";
    }

    virtual void
    QueryOutputProtectionStatus() override
    {
        LOGZ << "crcdm::Host::QueryOutputProtectionStatus\n";
    }

    virtual void
    OnDeferredInitializationDone(cdm::StreamType stream_type, cdm::Status decoder_status) override
    {
        LOGZ << "crcdm::Host::OnDeferredInitializationDone\n";
    }

    virtual cdm::FileIO *
    CreateFileIO(cdm::FileIOClient *client) override
    {
        LOGZ << "crcdm::Host::CreateFileIO\n";
        return nullptr;
    }

    Host(GMPDecryptorCallback *decryptor_cb, uint32_t create_session_token)
        : decryptor_cb_(decryptor_cb)
        , create_session_token_(create_session_token)
    {
    }

private:
    GMPDecryptorCallback *decryptor_cb_;
    uint32_t              create_session_token_;
};


struct HostFuncParamContainer {
    GMPDecryptorCallback *decryptor_cb;
    uint32_t              create_session_token;
};


void *
get_cdm_host_func(int host_interface_version, void *user_data)
{
    LOGF << format("crcdm::get_cdm_host_func host_interface_version=%d, user_data=%p\n") %
            host_interface_version % user_data;

    auto p = static_cast<HostFuncParamContainer *>(user_data);
    auto decryptor_cb = p->decryptor_cb;
    auto create_session_token = p->create_session_token;
    delete p;

    return static_cast<void *>(new crcdm::Host(decryptor_cb, create_session_token));
}

void
Initialize()
{
    LOGF << "crcdm::Initialize\n";
    INITIALIZE_CDM_MODULE();
}

void
Deinitialize()
{
    LOGF << "crcdm::Deinitialize\n";
    DeinitializeCdmModule();
}

cdm::ContentDecryptionModule *
CreateInstance(GMPDecryptorCallback *decryptor_cb, uint32_t create_session_token)
{
    LOGF << format("crcdm::CreateInstance decryptor_cb=%p\n") % decryptor_cb;

    const string key_system {"com.widevine.alpha"};

    auto p = new HostFuncParamContainer();
    p->decryptor_cb = decryptor_cb;
    p->create_session_token = create_session_token;

    void *ptr = CreateCdmInstance(cdm::ContentDecryptionModule::kVersion, key_system.c_str(),
                                  key_system.length(), get_cdm_host_func,
                                  static_cast<void *>(p));
    LOGF << "  --> " << ptr << "\n";

    return static_cast<cdm::ContentDecryptionModule *>(ptr);
}

} // namespace crcdm
