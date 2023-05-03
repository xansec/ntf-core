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

#include <ntccfg_bind.h>
#include <ntcf_system.h>
#include <ntcs_blobutil.h>
#include <ntsf_system.h>
#include <ntsi_listenersocket.h>
#include <ntsi_streamsocket.h>
//#include <bdlf_bind.h>
//#include <bdlf_placeholder.h>
//#include <bslma_allocator.h>
//#include <bslma_default.h>
//#include <bslmt_latch.h>
#include <bslmt_semaphore.h>
#include <bsls_assert.h>
//#include <bsls_timeinterval.h>
#include <bsl_iostream.h>

using namespace BloombergLP;

namespace Mayhem
{

  //ntcf::SystemGuard systemGuard(ntscfg::Signal::e_PIPE);

  ntsa::Error      error;
  bslmt::Semaphore semaphore;

  bsl::shared_ptr<ntci::Interface> interface;
  bsl::shared_ptr<ntci::StreamSocket> serverSocket;
  bsl::shared_ptr<ntci::ListenerSocket> listenerSocket;
  bsl::shared_ptr<ntci::StreamSocket> clientSocket;

  bool clientServerSetup() {

    // Create and start a pool of I/O threads.

    ntca::InterfaceConfig interfaceConfig;
    interfaceConfig.setThreadName("Mayhem!");

    interface = ntcf::System::createInterface(interfaceConfig);

    error = interface->start();
    //BSLS_ASSERT(!error);

    // Create a listener socket and begin listening.

    ntca::ListenerSocketOptions listenerSocketOptions;
    listenerSocketOptions.setTransport(ntsa::Transport::e_TCP_IPV4_STREAM);
    listenerSocketOptions.setSourceEndpoint(
                          ntsa::Endpoint(ntsa::Ipv4Address::loopback(), 0));

    listenerSocket = interface->createListenerSocket(listenerSocketOptions);

    error = listenerSocket->open();
    //BSLS_ASSERT(!error);

    error = listenerSocket->listen();
    //BSLS_ASSERT(!error);

    // Connect a socket to the listener.

    ntca::StreamSocketOptions streamSocketOptions;
    streamSocketOptions.setTransport(ntsa::Transport::e_TCP_IPV4_STREAM);

    clientSocket = interface->createStreamSocket(streamSocketOptions);

    ntca::ConnectOptions connectOptions;
    ntci::ConnectCallback connectCallback =
        clientSocket->createConnectCallback(
            [&](__attribute__((unused)) const bsl::shared_ptr<ntci::Connector>& connector,
                __attribute__((unused))const ntca::ConnectEvent&             event)
    {
        //BSLS_ASSERT(!event.context().error());
        semaphore.post();
    });


    error = clientSocket->connect(listenerSocket->sourceEndpoint(),
                                  connectOptions,
                                  connectCallback);
    //BSLS_ASSERT(!error);

    semaphore.wait();

    // Accept a connection from the listener socket's backlog.
    ntca::AcceptOptions acceptOptions;
    ntci::AcceptCallback acceptCallback =
        listenerSocket->createAcceptCallback(
            [&](__attribute__((unused)) const bsl::shared_ptr<ntci::Acceptor>&     acceptor,
                const bsl::shared_ptr<ntci::StreamSocket>& streamSocket,
                __attribute__((unused)) const ntca::AcceptEvent&                   event)
    {
        //BSLS_ASSERT(acceptor == listenerSocket);
        //BSLS_ASSERT(!event.context().error());
        serverSocket = streamSocket;
        semaphore.post();
    });

    error = listenerSocket->accept(acceptOptions, acceptCallback);
    //BSLS_ASSERT(!error);

    semaphore.wait();

    return true;
  }

  void clientServerTeardown()
  {
    // Close the listener socket.

    {
        ntci::CloseCallback closeCallback =
            listenerSocket->createCloseCallback([&]()
        {
            semaphore.post();
        });

        listenerSocket->close(closeCallback);
        semaphore.wait();
    }

    // Close the client socket.

    {
        ntci::CloseCallback closeCallback =
            clientSocket->createCloseCallback([&]()
        {
            semaphore.post();
        });

        clientSocket->close(closeCallback);
        semaphore.wait();
    }

    // Close the server socket.

    {
        ntci::CloseCallback closeCallback =
            serverSocket->createCloseCallback([&]()
        {
            semaphore.post();
        });

        serverSocket->close(closeCallback);
        semaphore.wait();
    }

    // Stop the pool of I/O threads.

    interface->shutdown();
    interface->linger();

  }

  extern "C" int LLVMFuzzerTestOneInput(const char *data, size_t size)
  {
    static bool initialized = clientServerSetup();


   // Send some data from the client to the server.

   const char       *k_CLIENT_DATA      = data;
   const bsl::size_t k_CLIENT_DATA_SIZE = size;

   bdlbb::Blob clientData(clientSocket->outgoingBlobBufferFactory().get());
   bdlbb::BlobUtil::append(&clientData, k_CLIENT_DATA, k_CLIENT_DATA_SIZE);

   ntca::SendOptions sendOptions;

   ntci::SendCallback sendCallback =
       clientSocket->createSendCallback(
           [&](__attribute__((unused)) const bsl::shared_ptr<ntci::Sender>& sender,
               __attribute__((unused)) const ntca::SendEvent&               event)
   {
       //BSLS_ASSERT(sender == clientSocket);
       //BSLS_ASSERT(!event.context().error());
       semaphore.post();
   });

   error = clientSocket->send(clientData, sendOptions, sendCallback);
   //BSLS_ASSERT(!error);

   semaphore.wait();

   // Receive the expected amount of data from the client.

   bdlbb::Blob serverData(serverSocket->outgoingBlobBufferFactory().get());

   ntca::ReceiveOptions receiveOptions;
   receiveOptions.setSize(k_CLIENT_DATA_SIZE);

   ntci::ReceiveCallback receiveCallback =
       serverSocket->createReceiveCallback(
           [&](__attribute__((unused)) const bsl::shared_ptr<ntci::Receiver>& receiver,
               const bsl::shared_ptr<bdlbb::Blob>     data,
               __attribute__((unused)) const ntca::ReceiveEvent&              event)
   {
       //BSLS_ASSERT(receiver == serverSocket);
       //BSLS_ASSERT(!event.context().error());
       serverData = *data;
       semaphore.post();
   });

   error = serverSocket->receive(receiveOptions, receiveCallback);
   //BSLS_ASSERT(!error);

   semaphore.wait();

   // Ensure the data received matches the data sent.

   //BSLS_ASSERT(bdlbb::BlobUtil::compare(clientData, serverData) == 0);
   if(bdlbb::BlobUtil::compare(clientData, serverData) != 0) std::terminate();

   clientServerTeardown();

   return 0;
 }

}
