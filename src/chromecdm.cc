#include "chromecdm.hh"
#include "log.hh"
#include <string>
#include <boost/format.hpp>
#include <chrono>


using std::string;
using boost::format;


namespace crcdm {

class Host final: public cdm::ContentDecryptionModule::Host {
public:

    virtual cdm::Buffer *
    Allocate(uint32_t capacity) override
    {
        LOGD << "crcdm::Host::Allocate\n";
        return nullptr;
    }

    virtual void
    SetTimer(int64_t delay_ms, void *context) override
    {
        LOGD << "crcdm::Host::SetTimer\n";
    }

    virtual cdm::Time
    GetCurrentWallTime() override
    {
        LOGD << "crcdm::Host::GetCurrentWallTime\n";
        namespace chrono = std::chrono;

        auto now = chrono::high_resolution_clock::now().time_since_epoch();
        auto microsecs = chrono::duration_cast<chrono::microseconds>(now).count();
        double d = microsecs / 1e6;

        return d;
    }

    virtual void
    OnResolveNewSessionPromise(uint32_t promise_id, const char *session_id,
                               uint32_t session_id_size) override
    {
        LOGD << "crcdm::Host::OnResolveNewSessionPromise\n";
    }

    virtual void
    OnResolvePromise(uint32_t promise_id) override
    {
        LOGD << "crcdm::Host::OnResolvePromise\n";
    }

    virtual void
    OnRejectPromise(uint32_t promise_id, cdm::Error error, uint32_t system_code,
                    const char *error_message, uint32_t error_message_size) override
    {
        LOGD << "crcdm::Host::OnRejectPromise\n";
    }

    virtual void
    OnSessionMessage(const char *session_id, uint32_t session_id_size,
                     cdm::MessageType message_type, const char *message, uint32_t message_size,
                     const char *legacy_destination_url,
                     uint32_t legacy_destination_url_length) override
    {
        LOGD << "crcdm::Host::OnSessionMessage\n";
    }

    virtual void
    OnSessionKeysChange(const char *session_id, uint32_t session_id_size,
                        bool has_additional_usable_key, const cdm::KeyInformation *keys_info,
                        uint32_t keys_info_count) override
    {
        LOGD << "crcdm::Host::OnSessionKeysChange\n";
    }

    virtual void
    OnExpirationChange(const char *session_id, uint32_t session_id_size,
                       cdm::Time new_expiry_time) override
    {
        LOGD << "crcdm::Host::OnExpirationChange\n";
    }

    virtual void
    OnSessionClosed(const char *session_id, uint32_t session_id_size) override
    {
        LOGD << "crcdm::Host::OnSessionClosed\n";
    }

    virtual void
    OnLegacySessionError(const char *session_id, uint32_t session_id_length, cdm::Error error,
                         uint32_t system_code, const char *error_message,
                         uint32_t error_message_length) override
    {
        LOGD << "crcdm::Host::OnLegacySessionError\n";
    }

    virtual void
    SendPlatformChallenge(const char *service_id, uint32_t service_id_size, const char *challenge,
                          uint32_t challenge_size) override
    {
        LOGD << "crcdm::Host::SendPlatformChallenge\n";
    }

    virtual void
    EnableOutputProtection(uint32_t desired_protection_mask) override
    {
        LOGD << "crcdm::Host::EnableOutputProtection\n";
    }

    virtual void
    QueryOutputProtectionStatus() override
    {
        LOGD << "crcdm::Host::QueryOutputProtectionStatus\n";
    }

    virtual void
    OnDeferredInitializationDone(cdm::StreamType stream_type, cdm::Status decoder_status) override
    {
        LOGD << "crcdm::Host::OnDeferredInitializationDone\n";
    }

    virtual cdm::FileIO *
    CreateFileIO(cdm::FileIOClient *client) override
    {
        LOGD << "crcdm::Host::CreateFileIO\n";
        return nullptr;
    }

    static Host *
    get_another_instance()
    {
        return new Host();
    }

protected:
    Host() {}

    virtual
    ~Host() {}
};


void *
get_cdm_host_func(int host_interface_version, void *user_data)
{
    LOGD << format("crcdm::get_cdm_host_func host_interface_version=%d, user_data=%p\n") %
            host_interface_version % user_data;

    return static_cast<void *>(crcdm::Host::get_another_instance());
}

void
Initialize()
{
    LOGD << "crcdm::Initialize\n";
    INITIALIZE_CDM_MODULE();
}

void
Deinitialize()
{
    DeinitializeCdmModule();
}

cdm::ContentDecryptionModule *
CreateInstance()
{
    const string key_system {"com.widevine.alpha"};

    void *ptr = CreateCdmInstance(cdm::ContentDecryptionModule::kVersion, key_system.c_str(),
                                  key_system.length(), get_cdm_host_func, (void *)0x12345);
    LOGD << "calling crcdm::CreateInstance gives " << ptr << "\n";

    return static_cast<cdm::ContentDecryptionModule *>(ptr);
}

} // namespace crcdm
