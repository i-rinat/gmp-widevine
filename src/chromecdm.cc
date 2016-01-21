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

#include "chromecdm.hh"
#include "log.hh"
#include <string>
#include <boost/format.hpp>
#include <chrono>
#include "firefoxcdm.hh"
#include <lib/RefCounted.h>


using std::string;
using boost::format;


namespace crcdm {

cdm::ContentDecryptionModule *crcdm_instance = nullptr;

class BufferImpl final : public cdm::Buffer {
public:
    BufferImpl(uint32_t capacity)
    {
        LOGF << boost::format("cdm::BufferImpl::BufferImpl this=%1%, capacity=%2%\n") % this %
                capacity;
        SetSize(capacity);
    }

    ~BufferImpl()
    {
        LOGF << boost::format("cdm::BufferImpl::~BufferImpl this=%1%\n") % this;
    }

    virtual void
    Destroy() override {
        LOGF << "cdm::BufferImpl::Destroy (void)\n";
        free(data_); data_ = nullptr; sz_ = 0;
        delete this;
    }

    virtual uint32_t
    Capacity() const override
    {
        LOGF << "cdm::BufferImpl::Capacity (void)\n";
        return sz_;
    }

    virtual uint8_t *
    Data() override
    {
        LOGF << "cdm::BufferImpl::Data (void)\n";
        return data_;
    }

    virtual void
    SetSize(uint32_t size) override
    {
        LOGF << boost::format("cdm::BufferImpl::SetSize size=%1%\n") % size;
        data_ = static_cast<uint8_t *>(realloc(static_cast<void *>(data_), size));
        sz_ = size;
    }

    virtual uint32_t
    Size() const
    {
        LOGF << "cdm::BufferImpl::Size (void)\n";
        return sz_;
    }

private:
    uint8_t *data_ = nullptr;
    uint32_t sz_ = 0;
};

class GMPRecordClientImpl final : public GMPRecordClient {
private:
    cdm::FileIOClient::Status
    to_FileIOClient_Status(GMPErr aStatus)
    {
        switch (aStatus) {
        case GMPNoErr:       return cdm::FileIOClient::kSuccess;
        case GMPRecordInUse: return cdm::FileIOClient::kInUse;
        default:             return cdm::FileIOClient::kError;
        }
    }

public:
    virtual void
    OpenComplete(GMPErr aStatus) override
    {
        LOGF << format("fxcdm::GMPRecordClientImpl::OpenComplete aStatus=%1%\n") % aStatus;
        file_io_client_->OnOpenComplete(to_FileIOClient_Status(aStatus));
    }

    virtual void
    ReadComplete(GMPErr aStatus, const uint8_t *aData, uint32_t aDataSize) override
    {
        LOGF << format("fxcdm::GMPRecordClientImpl::ReadComplete aStatus=%1%, aData=%2%, "
                "aDataSize=%3%\n") % aStatus % static_cast<const void *>(aData) % aDataSize;
        file_io_client_->OnReadComplete(to_FileIOClient_Status(aStatus), aData, aDataSize);
    }

    virtual void
    WriteComplete(GMPErr aStatus) override
    {
        LOGF << format("fxcdm::GMPRecordClientImpl::WriteComplete aStatus=%1%\n") % aStatus;
        file_io_client_->OnWriteComplete(to_FileIOClient_Status(aStatus));
    }

    void
    set_file_io_client(cdm::FileIOClient *file_io_client)
    {
        file_io_client_ = file_io_client;
    }

private:
    cdm::FileIOClient   *file_io_client_ = nullptr;
};

class FileIO final : public cdm::FileIO, public RefCounted {
public:
    virtual void
    Open(const char *file_name, uint32_t file_name_size) override
    {
        LOGF << format("crcdm::FileIO::Open file_name=%1%, file_name_size=%2%\n") %
                string(file_name, file_name_size) % file_name_size;

        fxcdm::get_platform_api()->createrecord(file_name, file_name_size, &rec_, &rec_client_);
        rec_client_.set_file_io_client(file_io_client_);
        rec_->Open();
    }

    virtual void
    Read() override
    {
        LOGF << "crcdm::FileIO::Read (void)\n";
        rec_->Read();
    }

    virtual void
    Write(const uint8_t *data, uint32_t data_size) override
    {
        LOGF << format("crcdm::FileIO::Write data=%1%, data_size=%2%\n") %
                static_cast<const void *>(data) % data_size;
        rec_->Write(data, data_size);
    }

    virtual void
    Close() override
    {
        LOGF << "crcdm::FileIO::Close (void)\n";
        rec_->Close();
        Release();
    }

    FileIO(cdm::FileIOClient *file_io_client)
        : file_io_client_(file_io_client)
    {
        AddRef();
    }

private:
    cdm::FileIOClient   *file_io_client_;
    GMPRecord           *rec_;
    GMPRecordClientImpl  rec_client_;
};


class Host final: public cdm::ContentDecryptionModule::Host {
public:
    virtual cdm::Buffer *
    Allocate(uint32_t capacity) override
    {
        LOGF << format("crcdm::Host::Allocate capacity=%1%\n") % capacity;
        return new BufferImpl(capacity);
    }

    virtual void
    SetTimer(int64_t delay_ms, void *context) override
    {
        LOGF << format("crcdm::Host::SetTimer delay_ms=%1%, context=%2%\n") % delay_ms % context;

        class Task final : public GMPTask {
        public:
            virtual void
            Destroy() { delete this; }

            virtual void
            Run() { crcdm::get()->TimerExpired(context_); }

            Task(void *context)
                : context_(context)
            {}
        private:
            void *context_;
        };

        // TODO: handle errors
        fxcdm::get_platform_api()->settimer(new Task(context), delay_ms);
    }

    virtual cdm::Time
    GetCurrentWallTime() override
    {
        LOGF << "crcdm::Host::GetCurrentWallTime (void)\n";

        auto wt = std::chrono::system_clock::now().time_since_epoch();
        int64_t milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(wt).count();
        double t = milliseconds / 1e3;
        LOGF << format("   --> %1$.3f\n") % t;

        return t;
    }

    virtual void
    OnResolveNewSessionPromise(uint32_t promise_id, const char *session_id,
                               uint32_t session_id_size) override
    {
        LOGF << format("crcdm::Host::OnResolveNewSessionPromise promise_id=%1%, session_id=%2%\n")
                % promise_id % string(session_id, session_id_size);

        fxcdm::host()->SetSessionId(create_session_token_, session_id, session_id_size);
        fxcdm::host()->ResolveLoadSessionPromise(promise_id, true);
    }

    virtual void
    OnResolvePromise(uint32_t promise_id) override
    {
        LOGF << format("crcdm::Host::OnResolvePromise promise_id=%1%\n") % promise_id;

        fxcdm::host()->ResolvePromise(promise_id);
    }

    virtual void
    OnRejectPromise(uint32_t promise_id, cdm::Error error, uint32_t system_code,
                    const char *error_message, uint32_t error_message_size) override
    {
        LOGF << format("crcdm::Host::OnRejectPromise promise_id=%1%, error=%2%, system_code=%3%, "
                "error_message=%4%, error_message_size=%5%\n") % promise_id % error % system_code %
                string(error_message, error_message_size) % error_message_size;

        auto to_GMPDOMException = [](cdm::Error error) {
            switch (error) {
            case cdm::kNotSupportedError:  return kGMPNotSupportedError;
            case cdm::kInvalidStateError:  return kGMPInvalidStateError;
            case cdm::kInvalidAccessError: return kGMPInvalidAccessError;
            case cdm::kQuotaExceededError: return kGMPQuotaExceededError;
            default:                       return kGMPInvalidStateError;
            }
        };

        fxcdm::host()->RejectPromise(promise_id, to_GMPDOMException(error), error_message,
                                     error_message_size);
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

        fxcdm::host()->SessionMessage(session_id, session_id_size,
                                      convert_to_GMPSessionMessageType(message_type),
                                      reinterpret_cast<const uint8_t *>(message), message_size);
    }

    virtual void
    OnSessionKeysChange(const char *session_id, uint32_t session_id_size,
                        bool has_additional_usable_key, const cdm::KeyInformation *keys_info,
                        uint32_t keys_info_count) override
    {
        LOGF << format("crcdm::Host::OnSessionKeysChange session_id=%1%, session_id_size=%2%, "
                "has_additional_usable_key=%3%, keys_info=%4%, keys_info_count=%5%\n") %
                string(session_id, session_id_size) % session_id_size % has_additional_usable_key %
                static_cast<const void *>(keys_info) % keys_info_count;

        auto to_GMPMediaKeyStatus = [](cdm::KeyStatus status) {
            switch (status) {
            case cdm::kUsable:           return kGMPUsable;
            case cdm::kInternalError:    return kGMPInternalError;
            case cdm::kExpired:          return kGMPExpired;
            case cdm::kOutputRestricted: return kGMPOutputRestricted;
            case cdm::kOutputDownscaled: return kGMPOutputDownscaled;
            case cdm::kStatusPending:    return kGMPStatusPending;
            case cdm::kReleased:         return kGMPReleased;
            default:                     return kGMPMediaKeyStatusInvalid;
            }
        };

        for (uint32_t k = 0; k < keys_info_count; k ++) {
            LOGF << format("   key = (%1%) %2%\n") % keys_info[k].status %
                    fxcdm::to_hex_string(keys_info[k].key_id, keys_info[k].key_id_size);

            fxcdm::host()->KeyStatusChanged(session_id, session_id_size, keys_info[k].key_id,
                                            keys_info[k].key_id_size,
                                            to_GMPMediaKeyStatus(keys_info[k].status));
        }
    }

    virtual void
    OnExpirationChange(const char *session_id, uint32_t session_id_size,
                       cdm::Time new_expiry_time) override
    {
        LOGF << format("crcdm::Host::OnExpirationChange session_id=%1%, session_id_size=%2%, "
                "new_expiry_time=%3$.3f\n") % string(session_id, session_id_size) %
                session_id_size % new_expiry_time;

        if (new_expiry_time != 0) {
            fxcdm::host()->ExpirationChange(session_id, session_id_size,
                                            static_cast<int64_t>(new_expiry_time * 1e3));
        }
    }

    virtual void
    OnSessionClosed(const char *session_id, uint32_t session_id_size) override
    {
        LOGF << format("crcdm::Host::OnSessionClosed session_id=%1%, session_id_size=%2%\n") %
                string(session_id, session_id_size) % session_id_size;

        fxcdm::host()->SessionClosed(session_id, session_id_size);
    }

    virtual void
    OnLegacySessionError(const char *session_id, uint32_t session_id_length, cdm::Error error,
                         uint32_t system_code, const char *error_message,
                         uint32_t error_message_length) override
    {
        LOGZ << format("crcdm::Host::OnLegacySessionError session_id=%1%, session_id_length=%2%, "
                "error=%3%, system_code=%4%, error_message=%5%, error_message_length=%6%\n") %
                string(session_id, session_id_length) % session_id_length % error % system_code %
                string(error_message, error_message_length) % error_message_length;
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
        LOGF << format("crcdm::Host::CreateFileIO client=%1%\n") % client;
        return new FileIO(client);
    }

    void
    set_create_session_token(uint32_t create_session_token)
    {
        create_session_token_ = create_session_token;
    }

private:
    uint32_t create_session_token_ = 0;
};

Host *crcdm_host_instance = nullptr;

void *
get_cdm_host_func(int host_interface_version, void *user_data)
{
    LOGF << format("crcdm::get_cdm_host_func host_interface_version=%d, user_data=%p\n") %
            host_interface_version % user_data;

    crcdm_host_instance = new crcdm::Host(); // XXX: relying on the fact the function is called
                                             //      once, which could be wrong

    return static_cast<void *>(crcdm_host_instance);
}

void
Initialize()
{
    LOGF << "crcdm::Initialize\n";
    INITIALIZE_CDM_MODULE();

    const string key_system {"com.widevine.alpha"};

    void *ptr = CreateCdmInstance(cdm::ContentDecryptionModule::kVersion, key_system.c_str(),
                                  key_system.length(), get_cdm_host_func, nullptr);

    LOGF << "  --> " << ptr << "\n";
    crcdm_instance = static_cast<cdm::ContentDecryptionModule *>(ptr);
    crcdm_instance->Initialize(true, true);     // TODO: allow_distinctive_identifier?
}

void
Deinitialize()
{
    LOGF << "crcdm::Deinitialize\n";
    DeinitializeCdmModule();
}

cdm::ContentDecryptionModule *
get()
{
    return crcdm_instance;
}

void
set_create_session_token(uint32_t create_session_token)
{
    crcdm_host_instance->set_create_session_token(create_session_token);
}

} // namespace crcdm
