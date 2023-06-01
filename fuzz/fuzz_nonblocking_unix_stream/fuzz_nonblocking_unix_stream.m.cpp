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

// Blantantly lifted from examples/m_ntsu03


#include <ntsf_system.h>
#include <ntsi_listenersocket.h>
#include <ntsi_streamsocket.h>
//#include <bsls_assert.h>
//#include <bsls_platform.h>

using namespace BloombergLP;


extern "C" int LLVMFuzzerTestOneInput(const char *data, size_t size)
{
  // Initialize the library.

  //static bool initialized = ntsf::System::initialize();
  ntsf::System::initialize();
  ntsf::System::ignore(ntscfg::Signal::e_PIPE);

  ntsa::Error error;

//#if defined(BSLS_PLATFORM_OS_UNIX)

  //
  // PART 1: LISTEN
  //

  // Create a blocking socket, bind it to any port on the loopback
  // address, then begin listening for connections.

  bsl::shared_ptr<ntsi::ListenerSocket> listener =
                                        ntsf::System::createListenerSocket();

  error = listener->open(ntsa::Transport::e_LOCAL_STREAM);
  //BSLS_ASSERT_OPT(!error);

  error = listener->bind(ntsa::Endpoint(ntsa::LocalName::generateUnique()),
                         false);
  //BSLS_ASSERT_OPT(!error);

  error = listener->listen(1);
  //BSLS_ASSERT_OPT(!error);

  //
  // PART 2: CONNECT
  //

  // Create a blocking socket for the client, then connect that socket to
  // the listener socket's local endpoint.

  bsl::shared_ptr<ntsi::StreamSocket> client =
                                          ntsf::System::createStreamSocket();

  error = client->open(ntsa::Transport::e_LOCAL_STREAM);
  //BSLS_ASSERT_OPT(!error);

  ntsa::Endpoint listenerEndpoint;
  error = listener->sourceEndpoint(&listenerEndpoint);
  //BSLS_ASSERT_OPT(!error);

  error = client->connect(listenerEndpoint);
  //BSLS_ASSERT_OPT(!error);

  //
  // PART 3: ACCEPT
  //

  // Create a blocking socket for the server by accepting the connection
  // made to the listener socket.

  bsl::shared_ptr<ntsi::StreamSocket> server;
  error = listener->accept(&server);
  //BSLS_ASSERT_OPT(!error);

  //
  // PART 4: SEND DATA FROM THE CLIENT TO THE SERVER
  //

  // Enqueue outgoing data to transmit by the client socket.

  {
      //char storage = 'C';

      ntsa::Data ntsa_data(ntsa::ConstBuffer(data, size));

      ntsa::SendContext context;
      ntsa::SendOptions options;

      error = client->send(&context, ntsa_data, options);
      //BSLS_ASSERT_OPT(!error);

      //BSLS_ASSERT_OPT(context.bytesSent() == 1);
  }

  // Dequeue incoming data received by the server socket.

  {
      char storage[size];

      ntsa::Data nsta_data(ntsa::MutableBuffer(&storage, size));

      ntsa::ReceiveContext context;
      ntsa::ReceiveOptions options;

      error = server->receive(&context, &ntsa_data, options);
      //BSLS_ASSERT_OPT(!error);

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

      error = client->receive(&context, &ntsa_data, options);
      //BSLS_ASSERT_OPT(!error);

      //BSLS_ASSERT_OPT(context.bytesReceived() == 1);
      //BSLS_ASSERT_OPT(storage == 'S');
  }

  //
  // PART 6: SHUTDOWN WRITING BY THE CLIENT
  //

  // Shutdown writing by the client socket.

  error = client->shutdown(ntsa::ShutdownType::e_SEND);
  //BSLS_ASSERT_OPT(!error);

  // Dequeue incoming data received by the server socket, and observe that
  // zero bytes are successfully dequeued, indicating the client socket has
  // shut down writing from its side of the connection.

  {
      char storage[size];

      ntsa::Data ntsa_data(ntsa::MutableBuffer(&storage, size));

      ntsa::ReceiveContext context;
      ntsa::ReceiveOptions options;

      error = server->receive(&context, &ntsa_data, options);
      //BSLS_ASSERT_OPT(!error);

      //BSLS_ASSERT_OPT(context.bytesReceived() == 0);
  }

  //
  // PART 7: SHUTDOWN WRITING BY THE SERVER
  //

  // Shutdown writing by the server socket.

  error = server->shutdown(ntsa::ShutdownType::e_SEND);
  //BSLS_ASSERT_OPT(!error);

  // Dequeue incoming data received by the client socket, and observe that
  // zero bytes are successfully dequeued, indicating the server socket has
  // shut down writing from its side of the connection.

  {
      char storage[size];

      ntsa::Data ntsa_data(ntsa::MutableBuffer(&storage, size));

      ntsa::ReceiveContext context;
      ntsa::ReceiveOptions options;

      error = client->receive(&context, &ntsa_data, options);
      //BSLS_ASSERT_OPT(!error);

      //BSLS_ASSERT_OPT(context.bytesReceived() == 0);
  }

//#endif

  return 0;
}
