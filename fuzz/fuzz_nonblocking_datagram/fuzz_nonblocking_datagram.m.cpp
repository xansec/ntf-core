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

// Blantantly lifted from examples/m_ntsu04

#include <ntsf_system.h>
#include <ntsi_datagramsocket.h>
//#include <bsls_assert.h>

using namespace BloombergLP;


extern "C" int LLVMFuzzerTestOneInput(const char *data, size_t size)
{
  // Initialize the library.

  static bool initialized = ntsf::System::initialize();
  ntsf::System::ignore(ntscfg::Signal::e_PIPE);

  ntsa::Error error;

  //
  // PART 1: BIND
  //

  // Create a blocking socket for the server and bind it to any port on the
  // loopback address.

  bsl::shared_ptr<ntsi::DatagramSocket> server =
                                        ntsf::System::createDatagramSocket();

  error = server->open(ntsa::Transport::e_UDP_IPV4_DATAGRAM);
  //BSLS_ASSERT_OPT(!error);

  error = server->bind(ntsa::Endpoint(ntsa::Ipv4Address::loopback(), 0),
                       false);
  //BSLS_ASSERT_OPT(!error);

  ntsa::Endpoint serverEndpoint;
  error = server->sourceEndpoint(&serverEndpoint);
  //BSLS_ASSERT_OPT(!error);

  // Create a blocking socket for the client and bind it to any port on the
  // loopback address.

  bsl::shared_ptr<ntsi::DatagramSocket> client =
                                        ntsf::System::createDatagramSocket();

  error = client->open(ntsa::Transport::e_UDP_IPV4_DATAGRAM);
  //BSLS_ASSERT_OPT(!error);

  error = client->bind(ntsa::Endpoint(ntsa::Ipv4Address::loopback(), 0),
                       false);
  //BSLS_ASSERT_OPT(!error);

  ntsa::Endpoint clientEndpoint;
  error = client->sourceEndpoint(&clientEndpoint);
  //BSLS_ASSERT_OPT(!error);

  //
  // PART 2: SEND DATA FROM THE CLIENT TO THE SERVER
  //

  // Enqueue outgoing data to transmit by the client socket.

  {
      //char storage = 'C';

      ntsa::Data ntsa_data(ntsa::ConstBuffer(data, size));

      ntsa::SendContext context;
      ntsa::SendOptions options;
      options.setEndpoint(serverEndpoint);

      error = client->send(&context, ntsa_data, options);
      //BSLS_ASSERT_OPT(!error);

      //BSLS_ASSERT_OPT(context.bytesSent() == 1);
  }

  // Dequeue incoming data received by the server socket.

  {
      char storage[size];

      ntsa::Data ntsa_data(ntsa::MutableBuffer(&storage, size));

      ntsa::ReceiveContext context;
      ntsa::ReceiveOptions options;
      options.showEndpoint();

      error = server->receive(&context, &ntsa_data, options);
      //BSLS_ASSERT_OPT(!error);

      //BSLS_ASSERT_OPT(context.endpoint().value() == clientEndpoint);
      //BSLS_ASSERT_OPT(context.bytesReceived() == 1);
      //BSLS_ASSERT_OPT(storage == 'C');
  }

  //
  // PART 5: SEND DATA FROM THE SERVER TO THE CLIENT
  //

  // Enqueue outgoing data to transmit by the server socket.

  {
      //char storage = 'S';

      ntsa::Data ntsa_data(ntsa::ConstBuffer(data, size));

      ntsa::SendContext context;
      ntsa::SendOptions options;
      options.setEndpoint(clientEndpoint);

      error = server->send(&context, ntsa_data, options);
      //BSLS_ASSERT_OPT(!error);

      //BSLS_ASSERT_OPT(context.bytesSent() == 1);
  }

  // Dequeue incoming data received by the client socket.

  {
      char storage[size];

      ntsa::Data ntsa_data(ntsa::MutableBuffer(&storage, size));

      ntsa::ReceiveContext context;
      ntsa::ReceiveOptions options;
      options.showEndpoint();

      error = client->receive(&context, &ntsa_data, options);
      //BSLS_ASSERT_OPT(!error);

      //BSLS_ASSERT_OPT(context.endpoint().value() == serverEndpoint);
      //BSLS_ASSERT_OPT(context.bytesReceived() == 1);
      //BSLS_ASSERT_OPT(storage == 'S');
  }

  return 0;
}
