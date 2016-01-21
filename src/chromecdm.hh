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

#pragma once

#include <stdlib.h>
#include <api/crcdm/content_decryption_module.h>
#include <api/gmp/gmp-decryption.h>
#include <boost/format.hpp>
#include "log.hh"


namespace crcdm {

void
Initialize();

void
Deinitialize();

cdm::ContentDecryptionModule *
get();

void
set_create_session_token(uint32_t create_session_token);


class VideoFrame final : public cdm::VideoFrame
{
public:
    virtual void
    SetFormat(cdm::VideoFormat fmt) override
    {
        LOGF << boost::format("crcdm::VideoFrame::SetFormat fmt=%1%\n") % fmt;
        fmt_ = fmt;
    }

    virtual cdm::VideoFormat
    Format() const override
    {
        LOGF << "crcdm::VideoFrame::Format (void)\n";
        return fmt_;
    }

    virtual void
    SetSize(cdm::Size size) override
    {
        LOGF << boost::format("crcdm::VideoFrame::SetSize size={.width=%1%, .height=%2%}\n") %
                size.width % size.height;
        size_ = size;
    }

    virtual cdm::Size
    Size() const override
    {
        LOGF << "crcdm::VideoFrame::Size (void)\n";
        return size_;
    }

    virtual void
    SetFrameBuffer(cdm::Buffer *frame_buffer) override
    {
        LOGF << boost::format("crcdm::VideoFrame::SetFrameBuffer frame_buffer=%1%\n") %
                static_cast<const void *>(frame_buffer);
        frame_buffer_ = frame_buffer;
    }

    virtual cdm::Buffer *
    FrameBuffer() override
    {
        LOGF << "crcdm::VideoFrame::FrameBuffer (void)\n";
        return frame_buffer_;
    }

    virtual void
    SetPlaneOffset(cdm::VideoFrame::VideoPlane plane, uint32_t offset) override
    {
        LOGF << boost::format("crcdm::VideoFrame::SetPlaneOffset plane=%1%, offset=%2%\n") % plane %
                offset;

        switch (plane) {
        case cdm::VideoFrame::kYPlane:
        case cdm::VideoFrame::kUPlane:
        case cdm::VideoFrame::kVPlane:
            plane_ofs_[plane] = offset;
            break;

        default:
            break;
        }
    }

    virtual uint32_t
    PlaneOffset(cdm::VideoFrame::VideoPlane plane) override
    {
        LOGF << boost::format("crcdm::VideoFrame::PlaneOffset plane=%1%\n") % plane;

        switch (plane) {
        case cdm::VideoFrame::kYPlane:
        case cdm::VideoFrame::kUPlane:
        case cdm::VideoFrame::kVPlane:
            return plane_ofs_[plane];

        default:
            return 0;
        }
    }

    virtual void
    SetStride(cdm::VideoFrame::VideoPlane plane, uint32_t stride) override
    {
        LOGF << boost::format("crcdm::VideoFrame::SetStride plane=%1%, stride=%2%\n") % plane %
                stride;

        switch (plane) {
        case cdm::VideoFrame::kYPlane:
        case cdm::VideoFrame::kUPlane:
        case cdm::VideoFrame::kVPlane:
            stride_[plane] = stride;
            break;

        default:
            break;
        }
    }

    virtual uint32_t
    Stride(cdm::VideoFrame::VideoPlane plane) override
    {
        LOGF << boost::format("crcdm::VideoFrame::Stride plane=%1%\n") % plane;

        switch (plane) {
        case cdm::VideoFrame::kYPlane:
        case cdm::VideoFrame::kUPlane:
        case cdm::VideoFrame::kVPlane:
            return stride_[plane];

        default:
            return 0;
        }
    }

    virtual void
    SetTimestamp(int64_t timestamp) override
    {
        LOGF << boost::format("crcdm::VideoFrame::SetTimestamp timestamp=%1%\n") % timestamp;
        timestamp_ = timestamp;
    }

    virtual int64_t
    Timestamp() const override
    {
        LOGF << "crcdm::VideoFrame::Timestamp (void)\n";
        return timestamp_;
    }

    ~VideoFrame() { LOGF << "crcdm::VideoFrame::~VideoFrame\n"; }

private:
    int64_t             timestamp_ = 0;
    cdm::VideoFormat    fmt_ = cdm::kUnknownVideoFormat;
    cdm::Size           size_;
    cdm::Buffer        *frame_buffer_ = nullptr;
    uint32_t            plane_ofs_[cdm::VideoFrame::kMaxPlanes] = {};
    uint32_t            stride_[cdm::VideoFrame::kMaxPlanes] = {};
};

} // namespace crcdm
