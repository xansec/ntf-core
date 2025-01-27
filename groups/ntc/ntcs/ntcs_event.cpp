// Copyright 2020-2023 Bloomberg Finance L.P.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <ntcs_event.h>

#include <bsls_ident.h>
BSLS_IDENT_RCSID(ntcs_event_cpp, "$Id$ $CSID$")

#include <bdlb_string.h>

#include <bslma_allocator.h>
#include <bslma_default.h>
#include <bslmf_assert.h>
#include <bsls_assert.h>
#include <bsls_platform.h>

#if defined(BSLS_PLATFORM_OS_WINDOWS)
#include <windows.h>
#endif

namespace BloombergLP {
namespace ntcs {

namespace {

void createEvent(void* arena, bslma::Allocator* allocator)
{
    // Create a new completion event in the specified 'arena'. Allocate
    // memory using the specified 'allocator'.

    new (arena) ntcs::Event(allocator);
}

}  // close unnamed namespace

int EventType::fromInt(EventType::Value* result, int number)
{
    switch (number) {
    case ntcs::EventType::e_UNDEFINED:
    case ntcs::EventType::e_CALLBACK:
    case ntcs::EventType::e_ACCEPT:
    case ntcs::EventType::e_CONNECT:
    case ntcs::EventType::e_SEND:
    case ntcs::EventType::e_RECEIVE:
        *result = static_cast<EventType::Value>(number);
        return 0;
    default:
        return -1;
    }
}

int EventType::fromString(EventType::Value*        result,
                          const bslstl::StringRef& string)
{
    if (bdlb::String::areEqualCaseless(string, "UNDEFINED")) {
        *result = e_UNDEFINED;
        return 0;
    }
    if (bdlb::String::areEqualCaseless(string, "CALLBACK")) {
        *result = e_CALLBACK;
        return 0;
    }
    if (bdlb::String::areEqualCaseless(string, "ACCEPT")) {
        *result = e_ACCEPT;
        return 0;
    }
    if (bdlb::String::areEqualCaseless(string, "CONNECT")) {
        *result = e_CONNECT;
        return 0;
    }
    if (bdlb::String::areEqualCaseless(string, "SEND")) {
        *result = e_SEND;
        return 0;
    }
    if (bdlb::String::areEqualCaseless(string, "RECEIVE")) {
        *result = e_RECEIVE;
        return 0;
    }

    return -1;
}

const char* EventType::toString(EventType::Value value)
{
    switch (value) {
    case ntcs::EventType::e_UNDEFINED:
        return "UNDEFINED";
    case ntcs::EventType::e_CALLBACK:
        return "CALLBACK";
    case ntcs::EventType::e_ACCEPT:
        return "ACCEPT";
    case ntcs::EventType::e_CONNECT:
        return "CONNECT";
    case ntcs::EventType::e_SEND:
        return "SEND";
    case ntcs::EventType::e_RECEIVE:
        return "RECEIVE";
    }

    return "???";
}

bsl::ostream& EventType::print(bsl::ostream& stream, EventType::Value value)
{
    return stream << toString(value);
}

bsl::ostream& operator<<(bsl::ostream& stream, EventType::Value rhs)
{
    return EventType::print(stream, rhs);
}

int EventStatus::fromInt(EventStatus::Value* result, int number)
{
    switch (number) {
    case ntcs::EventStatus::e_UNDEFINED:
    case ntcs::EventStatus::e_FREE:
    case ntcs::EventStatus::e_PENDING:
    case ntcs::EventStatus::e_CANCELLED:
    case ntcs::EventStatus::e_FAILED:
    case ntcs::EventStatus::e_COMPLETE:
        *result = static_cast<EventStatus::Value>(number);
        return 0;
    default:
        return -1;
    }
}

int EventStatus::fromString(EventStatus::Value*      result,
                            const bslstl::StringRef& string)
{
    if (bdlb::String::areEqualCaseless(string, "UNDEFINED")) {
        *result = e_UNDEFINED;
        return 0;
    }
    if (bdlb::String::areEqualCaseless(string, "FREE")) {
        *result = e_FREE;
        return 0;
    }
    if (bdlb::String::areEqualCaseless(string, "PENDING")) {
        *result = e_PENDING;
        return 0;
    }
    if (bdlb::String::areEqualCaseless(string, "CANCELLED")) {
        *result = e_CANCELLED;
        return 0;
    }
    if (bdlb::String::areEqualCaseless(string, "FAILED")) {
        *result = e_FAILED;
        return 0;
    }
    if (bdlb::String::areEqualCaseless(string, "COMPLETE")) {
        *result = e_COMPLETE;
        return 0;
    }

    return -1;
}

const char* EventStatus::toString(EventStatus::Value value)
{
    switch (value) {
    case ntcs::EventStatus::e_UNDEFINED:
        return "UNDEFINED";
    case ntcs::EventStatus::e_FREE:
        return "FREE";
    case ntcs::EventStatus::e_PENDING:
        return "PENDING";
    case ntcs::EventStatus::e_CANCELLED:
        return "CANCELLED";
    case ntcs::EventStatus::e_FAILED:
        return "FAILED";
    case ntcs::EventStatus::e_COMPLETE:
        return "COMPLETE";
    }

    return "???";
}

bsl::ostream& EventStatus::print(bsl::ostream&      stream,
                                 EventStatus::Value value)
{
    return stream << toString(value);
}

bsl::ostream& operator<<(bsl::ostream& stream, EventStatus::Value rhs)
{
    return EventStatus::print(stream, rhs);
}

Overlapped::Overlapped()
: d_rsv0(0)
, d_rsv1(0)
, d_rsv2(0)
, d_rsv3(0)
, d_rsv4(0)
{
#if defined(BSLS_PLATFORM_OS_WINDOWS)

    BSLMF_ASSERT(offsetof(Overlapped, d_rsv0) ==
                 offsetof(OVERLAPPED, Internal));

    BSLMF_ASSERT(sizeof(this->d_rsv0) ==
                 sizeof(reinterpret_cast<OVERLAPPED*>(this)->Internal));

    BSLMF_ASSERT(offsetof(Overlapped, d_rsv1) ==
                 offsetof(OVERLAPPED, InternalHigh));

    BSLMF_ASSERT(sizeof(this->d_rsv1) ==
                 sizeof(reinterpret_cast<OVERLAPPED*>(this)->InternalHigh));

    BSLMF_ASSERT(offsetof(Overlapped, d_rsv2) == offsetof(OVERLAPPED, Offset));

    BSLMF_ASSERT(sizeof(this->d_rsv2) ==
                 sizeof(reinterpret_cast<OVERLAPPED*>(this)->Offset));

    BSLMF_ASSERT(offsetof(Overlapped, d_rsv3) ==
                 offsetof(OVERLAPPED, OffsetHigh));

    BSLMF_ASSERT(sizeof(this->d_rsv3) ==
                 sizeof(reinterpret_cast<OVERLAPPED*>(this)->OffsetHigh));

    BSLMF_ASSERT(offsetof(Overlapped, d_rsv4) == offsetof(OVERLAPPED, hEvent));

    BSLMF_ASSERT(sizeof(this->d_rsv4) ==
                 sizeof(reinterpret_cast<OVERLAPPED*>(this)->hEvent));

    BSLMF_ASSERT(sizeof(Overlapped) == sizeof(OVERLAPPED));

#endif
}

Overlapped::Overlapped(const Overlapped& original)
: d_rsv0(original.d_rsv0)
, d_rsv1(original.d_rsv1)
, d_rsv2(original.d_rsv2)
, d_rsv3(original.d_rsv3)
, d_rsv4(original.d_rsv4)
{
}

Overlapped::~Overlapped()
{
}

Overlapped& Overlapped::operator=(const Overlapped& other)
{
    if (this != &other) {
        d_rsv0 = other.d_rsv0;
        d_rsv1 = other.d_rsv1;
        d_rsv2 = other.d_rsv2;
        d_rsv3 = other.d_rsv3;
        d_rsv4 = other.d_rsv4;
    }

    return *this;
}

void Overlapped::reset()
{
    d_rsv0 = 0;
    d_rsv1 = 0;
    d_rsv2 = 0;
    d_rsv3 = 0;
    d_rsv4 = 0;
}

Event::Event(bslma::Allocator* basicAllocator)
: d_overlapped()
, d_type(ntcs::EventType::e_UNDEFINED)
, d_status(ntcs::EventStatus::e_FREE)
, d_socket()
, d_target(ntsa::k_INVALID_HANDLE)
, d_receiveData_p(0)
, d_numBytesAttempted(0)
, d_numBytesCompleted(0)
, d_function(NTCCFG_FUNCTION_INIT(basicAllocator))
, d_error()
, d_operationMemory(0)
, d_operationMemorySize(0)
, d_operationArenaSize(0)
{
    bsl::memset(d_operationArena, 0, sizeof d_operationArena);

#if defined(BSLS_PLATFORM_OS_WINDOWS)
    BSLS_ASSERT(static_cast<void*>(this) == static_cast<void*>(&d_overlapped));
#endif
}

Event::Event(const Event& other, bslma::Allocator* basicAllocator)
: d_overlapped(other.d_overlapped)
, d_type(other.d_type)
, d_status(other.d_status)
, d_socket(other.d_socket)
, d_target(other.d_target)
, d_receiveData_p(other.d_receiveData_p)
, d_numBytesAttempted(other.d_numBytesAttempted)
, d_numBytesCompleted(other.d_numBytesCompleted)
, d_function(NTCCFG_FUNCTION_COPY(other.d_function, basicAllocator))
, d_error(other.d_error)
, d_operationMemory(other.d_operationMemory)
, d_operationMemorySize(other.d_operationMemorySize)
, d_operationArenaSize(other.d_operationArenaSize)
{
    bsl::memcpy(d_operationArena,
                other.d_operationArena,
                sizeof d_operationArena);
}

Event::~Event()
{
}

Event& Event::operator=(const Event& other)
{
    if (this != &other) {
        d_overlapped          = other.d_overlapped;
        d_type                = other.d_type;
        d_status              = other.d_status;
        d_socket              = other.d_socket;
        d_target              = other.d_target;
        d_receiveData_p       = other.d_receiveData_p;
        d_numBytesAttempted   = other.d_numBytesAttempted;
        d_numBytesCompleted   = other.d_numBytesCompleted;
        d_function            = other.d_function;
        d_error               = other.d_error;
        d_operationMemory     = other.d_operationMemory;
        d_operationMemorySize = other.d_operationMemorySize;
        bsl::memcpy(d_operationArena,
                    other.d_operationArena,
                    sizeof d_operationArena);
        d_operationArenaSize = other.d_operationArenaSize;
    }

    return *this;
}

// Reset the value of this object to its value upon default construction.
void Event::reset()
{
    d_overlapped.reset();
    d_type   = ntcs::EventType::e_UNDEFINED;
    d_status = ntcs::EventStatus::e_FREE;
    d_socket.reset();
    d_target              = ntsa::k_INVALID_HANDLE;
    d_receiveData_p       = 0;
    d_numBytesAttempted   = 0;
    d_numBytesCompleted   = 0;
    d_function            = Functor();
    d_error               = ntsa::Error();
    d_operationMemory     = 0;
    d_operationMemorySize = 0;
    if (d_operationArenaSize > 0) {
        BSLS_ASSERT_OPT(static_cast<bsl::size_t>(d_operationArenaSize) <=
                        sizeof(d_operationArena));
        bsl::memset(d_operationArena, 0, d_operationArenaSize);
    }
    d_operationArenaSize = 0;
}

bsl::ostream& operator<<(bsl::ostream& stream, const ntcs::Event& object)
{
    stream << "[ type = " << object.d_type;

    stream << "[ status = " << object.d_status;

    if (object.d_socket) {
        stream << " socket = " << object.d_socket->handle();
    }

    if (object.d_target != ntsa::k_INVALID_HANDLE) {
        stream << " target = " << object.d_target;
    }

    if (object.d_numBytesAttempted > 0) {
        stream << " attempted = " << object.d_numBytesAttempted;
        stream << " completed = " << object.d_numBytesCompleted;
    }

    if (object.d_error) {
        stream << " error = " << object.d_error.code() << " ("
               << object.d_error.number() << ")";
    }

    if (object.d_operationArena[0] != 0) {
        bsl::size_t size = bsl::strlen(object.d_operationArena);

        if (size > 0) {
            stream << " info = "
                   << bslstl::StringRef(object.d_operationArena, size);
        }
    }

    stream << " ]";

    return stream;
}

EventPool::EventPool(bslma::Allocator* basicAllocator)
: d_pool(&createEvent, basicAllocator)
, d_allocator_p(bslma::Default::allocator(basicAllocator))
{
}

EventPool::~EventPool()
{
}

}  // close package namespace
}  // close enterprise namespace
